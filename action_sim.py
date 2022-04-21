import time
from abc import ABC, abstractmethod
from subprocess import Popen
from typing import List, Type, Dict, Any

import virtkey


class ActionContext(Dict[str, Any]):
    def __init__(self, vk: virtkey.virtkey):
        super().__init__()
        self.vk = vk


class Action(ABC):
    @classmethod
    @abstractmethod
    def get_op_name(cls) -> str:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def create_from(cls, arg: str) -> 'Action':
        raise NotImplementedError()

    @abstractmethod
    def apply(self, ctx: ActionContext):
        raise NotImplementedError()


class AbstractKeyAction(Action, ABC):
    # https://github.com/h00s-python/ps3bdremote/blob/332ceb30c8bad5d8cb212824ccadda7164444e8d/virtualkey.py
    SPECIAL_KEYS = {
        'ctrl_left': 0xffe3, 'super_left': 0xffeb, 'alt_left': 0xffe9, 'alt_gr': 0xfe03, 'super_right': 0xffec, 'ctrl_right': 0xffe4,
        'shift_left': 0xffe1, 'shift_right': 0xffe2, 'caps_lock': 0xffe5, 'enter': 0xff0d, 'tab': 0xff09, 'backspace': 0xff08,
        'esc': 0xff1b, 'f1': 0xffbe, 'f2': 0xffbf, 'f3': 0xffc0, 'f4': 0xffc1, 'f5': 0xffc2, 'f6': 0xffc3, 'f7': 0xffc4, 'f8': 0xffc5, 'f9': 0xffc6, 'f10': 0xffc7, 'f11': 0xffc8, 'f12': 0xffc9,
        'scroll_lock': 0xff14, 'pause': 0xff13, 'insert': 0xff63, 'home': 0xff50, 'page_up': 0xff55, 'delete': 0xffff, 'end': 0xff57, 'page_down': 0xff56,
        'arrow_up': 0xff52, 'arrow_down': 0xff54, 'arrow_left': 0xff51, 'arrow_right': 0xff53, 'num_lock': 0xff63,
        'num_divide': 0xffaf, 'num_multiply': 0xffaa, 'num_subtract': 0xffad, 'num_add': 0xffab, 'num_enter': 0xff8d, 'num_0': 0xffb0, 'num_1': 0xffb1, 'num_2': 0xffb2, 'num_3': 0xffb3,
        'num_4': 0xffb4, 'num_5': 0xffb5, 'num_6': 0xffb6, 'num_7': 0xffb7, 'num_8': 0xffb8, 'num_9': 0xffb9, 'num_separator': 0xffac
    }

    def __init__(self, key_seq: str):
        self.sequence: List[int] = self.__read(key_seq)

    @classmethod
    def __read(cls, key_seq) -> List[int]:
        ret = []
        esc_flag = False
        special_flag = False
        special_key = ''
        for ch in key_seq:
            if not esc_flag:
                if ch == '[':
                    special_flag = True
                    continue
                elif ch == ']':
                    special_flag = False
                    assert special_key in cls.SPECIAL_KEYS, 'unknown special key: {}'.format(special_key)
                    ret.append(cls.SPECIAL_KEYS[special_key])
                    special_key = ''
                    continue
                elif ch == '\\':
                    esc_flag = True
                    continue
            # read normally
            esc_flag = False
            if special_flag:
                special_key += ch.lower()
            else:
                ret.append(ord(ch))
        return ret

    @classmethod
    def create_from(cls, arg: str) -> 'AbstractKeyAction':
        return cls(arg)

    @classmethod
    def __apply_key_delay(cls, ctx: ActionContext):
        delay = ctx.get('key_delay')
        if isinstance(delay, float) and delay > 0:
            time.sleep(delay)

    @classmethod
    def press(cls, ctx: ActionContext, keycode: int):
        ctx.vk.press_keysym(keycode)
        cls.__apply_key_delay(ctx)

    @classmethod
    def release(cls, ctx: ActionContext, keycode: int):
        ctx.vk.release_keysym(keycode)
        cls.__apply_key_delay(ctx)


class KeyPressAction(AbstractKeyAction):
    @classmethod
    def get_op_name(cls) -> str:
        return 'press'

    def apply(self, ctx: ActionContext):
        for ch in self.sequence:
            self.press(ctx, ch)


class KeyReleaseAction(AbstractKeyAction):
    @classmethod
    def get_op_name(cls) -> str:
        return 'release'

    def apply(self, ctx: ActionContext):
        for ch in self.sequence:
            self.release(ctx, ch)


class KeyInputAction(AbstractKeyAction):
    @classmethod
    def get_op_name(cls) -> str:
        return 'input'

    def apply(self, ctx: ActionContext):
        for ch in self.sequence:
            self.press(ctx, ch)
            self.release(ctx, ch)


class SleepAction(Action):
    def __init__(self, duration: float):
        self.duration = duration

    @classmethod
    def get_op_name(cls) -> str:
        return 'sleep'

    @classmethod
    def create_from(cls, arg: str) -> 'SleepAction':
        return SleepAction(float(arg))

    def apply(self, ctx: virtkey.virtkey):
        time.sleep(self.duration)


class SetKeyDelayAction(Action):
    def __init__(self, delay: float):
        self.delay = delay

    @classmethod
    def get_op_name(cls) -> str:
        return 'set_key_delay'

    @classmethod
    def create_from(cls, arg: str) -> 'SetKeyDelayAction':
        return SetKeyDelayAction(float(arg))

    def apply(self, ctx: ActionContext):
        ctx['key_delay'] = self.delay


class SetClipboardAction(Action):
    def __init__(self, content: str):
        self.content = content

    @classmethod
    def get_op_name(cls) -> str:
        return 'set_clipboard'

    @classmethod
    def create_from(cls, arg: str) -> 'SetClipboardAction':
        return SetClipboardAction(arg)

    def apply(self, ctx: virtkey.virtkey):
        import pyperclip
        pyperclip.copy(self.content)


class ActionSimulator:
    actions = [
        KeyPressAction,
        KeyReleaseAction,
        KeyInputAction,
        # doesn't work, why
        # SetClipboardAction,
        SetKeyDelayAction,
        SleepAction
    ]

    def __init__(self, command: str):
        self.__command: str = command
        self.__v = virtkey.virtkey()
        self.__actions: List[Action] = []

    def add_action(self, action: Action):
        self.__actions.append(action)

    def run(self) -> int:
        process = Popen(self.__command, shell=True)
        ctx = ActionContext(self.__v)
        for action in self.__actions:
            action.apply(ctx)
        process.wait()
        return process.returncode

    def read_file(self, file_path: str):
        op_map: Dict[str, Type[Action]] = dict(map(lambda a: (a.get_op_name(), a), self.actions))
        with open(file_path, 'r', encoding='utf8') as file:
            for i, line in enumerate(file.readlines()):
                line_num = i + 1
                line = line.strip()
                if len(line) == 0 or line.startswith('#'):
                    continue
                assert ' ' in line, '({}) Invalid Operation line: no space is found'.format(line_num)
                op, arg = line.split(' ', 1)
                assert op in op_map, '({}) Unknown operation: {}'.format(line_num, op)
                try:
                    action = op_map[op].create_from(arg)
                except Exception as e:
                    raise ValueError('({}) Failed to read argument: {}'.format(line_num, e))
                self.add_action(action)


def example():
    sim = ActionSimulator('vim')
    sim.read_file('action.txt')
    sim.run()


if __name__ == '__main__':
    # example()
    pass
