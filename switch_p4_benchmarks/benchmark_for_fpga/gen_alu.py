num_of_alu = 7
out_str = ""
for i in range(num_of_alu):
    if i == 0:
        out_str += "'ALU" + str(i + 1) + "'"
    else:
        out_str += ",'ALU" + str(i + 1) + "'"
print(out_str)