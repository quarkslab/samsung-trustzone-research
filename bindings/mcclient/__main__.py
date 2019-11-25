from IPython.terminal.embed import InteractiveShellEmbed

from . import mcclient


def main():
    banner = "Welcome to the Python mcClient API shell!\n\n"
    banner += "(check out the documentation to get started)\n"

    imcsh = InteractiveShellEmbed(banner1=banner, exit_msg="Bye o/\n")
    imcsh(local_ns={name: getattr(mcclient, name) for name in dir(mcclient)})


if __name__ == "__main__":
    main()
