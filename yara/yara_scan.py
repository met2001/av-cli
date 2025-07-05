import yara
import sys

def main():
    filepath = sys.argv[1]
    rules = yara.compile(filepath=r"C:\\Repos\\av-cli\\yara\\rules\\rules.yar") # CHANGE PATH TO RULES.YAR FILE ON YOUR PC
    matches = rules.match(filepath)

    if matches:
        for match in matches:
            print(f"> Rule: {match.rule}")
    else:
        print("> No YARA matches")


if __name__ == "__main__":
    main()