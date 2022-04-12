# table_l = ['ingress_port_properties', 'validate_outer_ipv4_packet', 'marple_tcp_nmo_table']
# table_act_dic = {'validate_outer_ipv4_packet':['set_valid_outer_ipv4_packet', 'set_malformed_outer_ipv4_packet'],
#                     'ingress_port_properties':['set_ingress_port_properties'],
#                     'marple_tcp_nmo_table':['marple_tcp_nmo']}
# action_alu_dic = {'ingress_port_properties': {'set_ingress_port_properties' : ['ALU1','ALU2','ALU3','ALU4','ALU5','ALU6','ALU7']},
#                         'validate_outer_ipv4_packet': {'set_valid_outer_ipv4_packet':['ALU1','ALU2','ALU3'], 'set_malformed_outer_ipv4_packet':['ALU1','ALU2']},
#                         'marple_tcp_nmo_table': {'marple_tcp_nmo':['ALU1','ALU2','ALU3']}} #key: table name, val: dictionary whose key is action name and whose value is list of alus
table_l = ['fabric_ingress_dst_lkp', 'storm_control', 'marple_tcp_nmo_table']
table_act_dic = {'fabric_ingress_dst_lkp':['switch_fabric_unicast_packet','terminate_fabric_unicast_packet','switch_fabric_multicast_packet','terminate_fabric_multicast_packet','terminate_cpu_packet'],
                    'storm_control':['set_storm_control_meter'],
                    'marple_tcp_nmo_table':['marple_tcp_nmo']}
action_alu_dic = {'fabric_ingress_dst_lkp': {'terminate_cpu_packet':['ALU1','ALU2','ALU3','ALU4'], 
                                                'switch_fabric_unicast_packet':['ALU1','ALU2','ALU3'], 
                                                'terminate_fabric_unicast_packet':['ALU1','ALU2','ALU3','ALU4','ALU5','ALU6','ALU7'],
                                                'switch_fabric_multicast_packet':['ALU1','ALU2'], 
                                                'terminate_fabric_multicast_packet':['ALU1','ALU2','ALU3','ALU4','ALU5','ALU6','ALU7']},
                        'storm_control': {'set_storm_control_meter':['ALU1']},
                        'marple_tcp_nmo_table': {'marple_tcp_nmo':['ALU1','ALU2','ALU3']}
                        }
for t in action_alu_dic:
    for a in action_alu_dic[t]:
        for alu in action_alu_dic[t][a]:
            print("'"+t+"_"+a+"_"+alu+"'")