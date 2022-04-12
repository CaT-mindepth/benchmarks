num_of_pkt = 35
out_str = 'pkt_fields_def = ['
for i in range(num_of_pkt):
    if i == num_of_pkt - 1:
        out_str += "'pkt_" + str(i) + "']"
    else:
        out_str += "'pkt_" + str(i) + "',"
print(out_str)
