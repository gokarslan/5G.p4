with open("a", "r") as f:
    data = f.read()
result = ""
for line in data.split("\n"):
    new_line = "PROCEDURE_"
    for (i, chr) in enumerate(line):
        if i == 0:
            new_line += chr
            chr.capitalize()
            continue
        if chr.isupper():
            if i > 0  and not line[i-1].isupper():
                new_line += "_" + chr
            elif i < len(line) and not line[i+1].isupper():
                new_line += "_" + chr
            else:
                new_line += chr
        else:
            new_line += chr
    result += "const bit<16> " + new_line.upper() + ";\n"

print(result)