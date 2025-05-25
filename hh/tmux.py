"""
To interactiv with a tmux session
"""
import libtmux
from libtmux import Pane, Window
import libtmux.exc
import log
from typing import Union

TMUX_SESSION_NAME = '0'
TMUX_WINDOW_NAME = 'hh'


def pane_send_keys(pane: Pane, keys, enter=True, print_log=True):
    """
    convinience function to send_keys
    I can just disable it here to globally track log messages and execution
    """
    if print_log:
        log.debug(f'Executing {keys}')

    try:
        pane.send_keys(keys, enter=enter)
    except Exception as e:
        log.debug(f'Error sending keys {e}')


def get_inactive_pane(window: Window) -> Union[Pane | None]:
    """
    Returns a pane that is currently inactive
    """
    for pane in window.panes:
        if pane.pane_current_command == 'zsh':
            return pane

    # create a new pane
    try:
        pane = window.split()
    except libtmux.exc.LibTmuxException as e:
        log.critical('Not enough space for TMUX pane')
        return

    return pane


def get_hh_pane(tmux_window_name='hh', select_window=False) -> Pane:
    srv = libtmux.Server()
    if not srv:
        log.debug('No tmux session running, creating session')
        srv.new_session()

    # doesn't make sense to code multiple session support now
    session = next((x for x in srv.list_sessions() if x.session_name == TMUX_SESSION_NAME), None)

    # we will create or reuse the window with the name "hh"

    window = next((x for x in session.list_windows() if x.name == tmux_window_name), None)

    if not window:
        window = session.new_window(tmux_window_name)

    if select_window:
        window.select()

    pane = get_inactive_pane(window)
    if not pane:
        log.debug(f'Could not identify {tmux_window_name} pane')
    return pane


def get_sliver_pane(pane_name='sliver-client') -> Pane:
    srv = libtmux.Server()
    if not srv:
        log.debug('No tmux session running, creating session')
        srv.new_session()

    # doesn't make sense to code multiple session support now
    session = next((x for x in srv.sessions if x.session_name == TMUX_SESSION_NAME), None)

    sliver_pane = None
    for window in session.windows:
        for pane in window.panes:
            if pane.pane_current_command == pane_name:
                sliver_pane = pane
                break

        # exit early if found
        if sliver_pane:
            break

    if not sliver_pane:
        log.debug(f'Could not find {pane_name} pane')

    return sliver_pane
