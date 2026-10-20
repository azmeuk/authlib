import functools
import inspect
import types
import weakref
from collections import defaultdict

_HOOKED_FUNCTIONS = weakref.WeakSet()


class Hookable:
    """Let hooks run before, after, or instead of any method of a subclass.

    Static methods, class methods, properties and dunder methods cannot be
    hooked.
    """

    _hooks = None

    def __init__(self):
        self._hooks = defaultdict(dict)

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        for name in dir(cls):
            if name.startswith("__") and name.endswith("__"):
                continue
            if name in Hookable.__dict__:
                continue
            method = inspect.getattr_static(cls, name)
            if isinstance(method, types.FunctionType) and not _is_hooked(method):
                setattr(cls, name, _hook_method(method))

    def register_hook(
        self, hook_or_name, hook=None, /, *, before=None, after=None, replace=None
    ):
        """Register a hook on a method.

        Pass the hook, and the method in ``before``, ``after`` or ``replace``::

            grant.register_hook(
                validate_code_verifier,
                after=AuthorizationCodeGrant.validate_token_request,
            )

        Or pass a hook name, such as ``"after_validate_token_request"``,
        and then the hook::

            grant.register_hook("after_validate_token_request", validate_code_verifier)

        A ``before`` hook receives ``(instance, *args, **kwargs)``.
        An ``after`` hook receives ``(instance, result)``.
        A ``replace`` hook receives ``(instance, original, *args, **kwargs)``,
        where ``original`` calls the method::

            def replace_hook(instance, original, *args, **kwargs):
                return original(*args, **kwargs)

        Hooks run in the order they are registered.
        When a method is overridden, the hooks run around the override.

        :param hook_or_name: The hook, or a hook name.
        :param hook: The hook, when the first argument is a hook name.
        :param before: The method the hook runs before.
        :param after: The method the hook runs after.
        :param replace: The method the hook runs instead of.
        :raises TypeError: If the method cannot be hooked,
            or if the arguments do not match one of the two forms.
        """
        targets = {"before": before, "after": after, "replace": replace}
        targets = {phase: method for phase, method in targets.items() if method}

        if isinstance(hook_or_name, str):
            if hook is None or targets:
                raise TypeError("A hook name must be followed by the hook only.")
            self._hooks[hook_or_name][hook] = None
            return

        if hook is not None or len(targets) != 1:
            raise TypeError("Pass exactly one of 'before', 'after' or 'replace'.")

        ((phase, method),) = targets.items()
        name = getattr(method, "__name__", None)
        if not name or not _is_hooked(getattr(type(self), name, None)):
            raise TypeError(f"{type(self).__qualname__} cannot hook {method!r}.")

        self._hooks[f"{phase}_{name}"][hook_or_name] = None

    def execute_hook(self, hook_type, *args, **kwargs):
        for hook in list(self._hooks.get(hook_type, ())):
            hook(self, *args, **kwargs)


def _hook_method(func):
    """Wrap a method so that its hooks run before, after, or instead of it.

    The hooks only run in the most derived implementation of the method.
    So they run once when an override calls super().
    """
    name = func.__name__
    before_name = f"before_{name}"
    after_name = f"after_{name}"
    replace_name = f"replace_{name}"

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        hooks = self._hooks or {}
        has_hooks = before_name in hooks or after_name in hooks or replace_name in hooks
        if not has_hooks or getattr(type(self), name, None) is not wrapper:
            return func(self, *args, **kwargs)

        self.execute_hook(before_name, *args, **kwargs)

        def effective_call(*a, **kw):
            return func(self, *a, **kw)

        def chain(hook, prev):
            def call(*a, **kw):
                return hook(self, prev, *a, **kw)

            return call

        for hook in list(self._hooks.get(replace_name, ())):
            effective_call = chain(hook, effective_call)

        result = effective_call(*args, **kwargs)
        self.execute_hook(after_name, result)
        return result

    _HOOKED_FUNCTIONS.add(wrapper)
    return wrapper


def _is_hooked(method):
    """Tell whether a function or a bound method runs hooks."""
    return getattr(method, "__func__", method) in _HOOKED_FUNCTIONS
