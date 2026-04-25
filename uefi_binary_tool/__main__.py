try:
    from .ui.app import main
except ModuleNotFoundError as exc:
    if exc.name != "_tkinter":
        raise
    from .web.app import main


if __name__ == "__main__":
    main()
