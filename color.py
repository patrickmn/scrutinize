import config

color_tag = '@'

color_black = "[0;30m"
color_red = "[0;31m"
color_green = "[0;32m"
color_yellow = "[0;33m"
color_blue = "[0;34m"
color_magenta = "[0;35m"
color_cyan = "[0;36m"
color_white = "[0;37m"
color_default = "[0;39m"
color_gray = "[1;30m"
color_bright_red = "[1;31m"
color_bright_green = "[1;32m"
color_bright_yellow = "[1;33m"
color_bright_blue = "[1;34m"
color_bright_magenta = "[1;35m"
color_bright_cyan = "[1;36m"
color_bright_white = "[1;37m"
color_bright_default = "[1;39m"

color_codes = {
    'r': color_red,
    'g': color_green,
    'b': color_blue,
    'y': color_yellow,
    'c': color_cyan,
    'm': color_magenta,
    'w': color_white,
    'x': color_default,
    'R': color_bright_red,
    'G': color_bright_green,
    'B': color_bright_blue,
    'Y': color_bright_yellow,
    'C': color_bright_cyan,
    'M': color_bright_magenta,
    'W': color_bright_white,
    'D': color_gray,
}

def substituteColorTags(text):
    for code in color_codes.keys():
        text = text.replace(color_tag + code, color_codes[code])
    return text

def stripColorTags(text):
    for code in color_codes.keys():
        text = text.replace(color_tag + code, '')
    return text

def colorize(text):
    if config.color:
        return substituteColorTags(text)
    else:
        return stripColorTags(text)
