#!/usr/bin/env python3

from termcolor import colored
from random import choice


class PeaceOut:
    """This script didn't have enough naked chicks so I added one."""

    def __init__(self):
        self.banner = """"""

    def bannerOut(self):
        """Select a random color from valid colors and return a random color
        to colorize the PeaceOut Banner Class."""

        def random_color(self):
            valid_colors = ("red", "green", "yellow", "blue", "magenta", "cyan")
            return choice(valid_colors)

        peace = """
    o o o o o o o . . .   ______________________________ _____=======_||____
   o      _____           ||                            | |                 |
 .][__n_n_|DD[  ====_____  |       O.G. Auto-Recon      | |      YESIR      |
>(________|__|_[_________]_|____________________________|_|_________________|
_/oo OOOOO oo`  ooo   ooo  'o!o!o                  o!o!o` 'o!o         o!o`
-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
                        """

        def print_art(self, msg, color):
            colored_art = colored(msg, color=color)
            print(colored_art)

        msg = peace
        color = random_color(self)
        print_art(self, msg, color)
        self.banner = peace


class heartbleed:
    def __init__(self, target):
        self.target = target
        self.blood_banner = """"""

    def bleedOut(self):
        """Select a random color from valid colors and return a random color
        to colorize the Banner."""

        bleed = rf"""
          |  \ \ | |/ /
          |  |\ `' ' /
          |  ;'aorta \      / , pulmonary
          | ;    _,   |    / / ,  arteries
 superior | |   (  `-.;_,-' '-' ,
vena cava | `,   `-._       _,-'_
          |,-`.    `.)    ,<_,-'_, pulmonary
         ,'    `.   /   ,'  `;-' _,  veins
        ;        `./   /`,    \-'
        | right   /   |  ;\   |\
        | atrium ;_,._|_,  `, ' \      √v^√v^♥√v^√v^√
        |        \    \ `       `,
        `      __ `    \   left  ;,
         \   ,'  `      \,  ventricle
          \_(            ;,      ;;
          |  \           `;,     ;;
 inferior |  |`.          `;;,   ;'
vena cava |  |  `-.        ;;;;,;' FL
          |  |    |`-.._  ,;;;;;'
          |  |    |   | ``';;;' {self.target} is vulnerable to heartbleed!!
          |__|   aorta                 ______.   .___                   ____.
          |  |__   ____ _____ ________/  |\_ |__ |  |   ____   ____   __| _/
          |  |  \_/ __ \\__  \\_  __ \   __\ __ \|  | _/ __ \_/ __ \ / __ | 
          |   Y  \  ___/ / __ \|  | \/|  | | \_\ \  |_\  ___/\  ___// /_/ | 
          |___|  /\___  >____  /__|   |__| |___  /____/\___  >\___  >____ | 
              \/     \/     \/                \/          \/     \/     \/ 
                        """

        def print_art(self, msg):
            colored_art = colored(msg, "red")
            print(colored_art)

        msg = bleed
        print_art(self, msg)
        self.blood_banner = bleed
