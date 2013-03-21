class OntologyRanker

  WEIGHT = { 1070 => 1000, 1506 => 999, 1032 => 998, 1351 => 997, 1123 => 996, 1053 => 995, 1353 => 994, 1132 => 993, 1007 => 992, 1006 => 991, 1009 => 990, 1125 => 989, 1136 => 988, 1084 => 987, 1332 => 986, 1107 => 985, 1057 => 984, 1062 => 983, 1069 => 982, 1012 => 981, 1025 => 980, 1109 => 979, 1101 => 978, 1498 => 977, 1498 => 976, 1498 => 975, 1290 => 974, 1350 => 973, 1092 => 972, 1000 => 971, 1112 => 970, 1158 => 969, 1108 => 968, 1083 => 967, 1587 => 966, 1038 => 965, 1038 => 964, 1001 => 963, 1245 => 962, 1541 => 961, 1533 => 960, 1106 => 959, 1005 => 958, 1013 => 957, 1321 => 956, 1046 => 955, 1042 => 954, 1352 => 953, 1423 => 952, 1348 => 951, 1035 => 950, 1076 => 949, 1054 => 948, 1068 => 947, 1082 => 946, 1010 => 945, 1047 => 944, 1001 => 943, 1104 => 942, 1397 => 941, 1131 => 940, 1033 => 939, 1314 => 938, 1051 => 937, 1089 => 936, 1016 => 935, 1105 => 934, 1142 => 933, 1023 => 932, 1041 => 931, 1149 => 930, 1507 => 929, 1031 => 928, 1085 => 927, 1414 => 926, 1087 => 925, 1114 => 924, 1633 => 923, 1560 => 922, 1040 => 921, 1090 => 920, 1015 => 919, 1172 => 918, 1134 => 917, 1126 => 916, 1021 => 915, 1011 => 914, 1095 => 913, 1422 => 912, 1347 => 911, 1427 => 910, 1344 => 909, 1341 => 908, 1354 => 907, 1349 => 906, 1699 => 905, 1343 => 904, 1019 => 903, 1099 => 902, 1049 => 901, 1413 => 900, 1058 => 899, 1067 => 898, 1152 => 897, 1059 => 896, 1148 => 895, 1532 => 894, 1613 => 893, 1190 => 892, 1048 => 891, 1043 => 890, 1150 => 889, 1061 => 888, 1056 => 887, 1304 => 886, 1130 => 885, 1100 => 884, 1039 => 883, 1222 => 882, 1026 => 881, 1393 => 880, 1404 => 879, 1510 => 878, 1401 => 877, 1489 => 876, 1568 => 875, 1487 => 874, 1370 => 873, 1419 => 872, 1381 => 871, 1402 => 870, 1529 => 869, 1108 => 868, 1038 => 867, 1146 => 866, 1516 => 865, 1050 => 864, 1036 => 863, 1424 => 862, 1426 => 861, 1430 => 860, 1037 => 859, 1078 => 858, 1044 => 857, 1444 => 856, 1001 => 855, 1110 => 854, 1141 => 853, 1081 => 852, 1064 => 851, 1077 => 850, 1237 => 849, 1122 => 848, 1128 => 847, 1585 => 846, 1030 => 845, 1065 => 844, 1311 => 843, 1639 => 842, 1438 => 841, 1505 => 840, 1581 => 839, 1580 => 838, 1522 => 837, 1398 => 836, 1528 => 835, 1574 => 834, 1650 => 833, 1504 => 832, 1429 => 831, 1553 => 830, 1425 => 829, 1526 => 828, 1527 => 827, 1489 => 826, 1621 => 825, 3020 => 824, 1521 => 823, 1539 => 822, 1091 => 821, 1632 => 820, 1115 => 819, 1094 => 818, 1063 => 817, 1060 => 816, 1183 => 815, 1052 => 814, 1116 => 813, 1055 => 812, 1192 => 811, 1022 => 810, 1088 => 809, 1086 => 808, 1027 => 807, 1029 => 806, 1135 => 805, 1144 => 804, 1017 => 803, 1024 => 802, 1328 => 801, 1008 => 800, 1415 => 799, 1586 => 798, 1411 => 797, 3008 => 796, 1576 => 795, 1497 => 794, 1640 => 793, 3016 => 792, 1440 => 791, 1461 => 790, 1578 => 789, 1550 => 788, 1565 => 787, 1530 => 786, 1631 => 785, 1569 => 784, 1509 => 783, 1501 => 782, 1409 => 781, 1494 => 780, 1570 => 779, 1571 => 778, 1537 => 777, 1651 => 776, 3030 => 775, 1696 => 774, 3003 => 773, 1362 => 772, 1658 => 771, 1247 => 770, 1638 => 769, 1517 => 768, 1417 => 767, 1410 => 766, 1672 => 765, 1394 => 764, 1582 => 763, 1524 => 762, 1523 => 761, 1540 => 760, 1335 => 759, 1369 => 758, 1399 => 757, 1538 => 756, 1249 => 755, 3114 => 754, 1588 => 753, 1500 => 752, 1257 => 751, 3108 => 750, 3042 => 749, 3002 => 748, 1418 => 747, 1671 => 746, 3013 => 745, 1686 => 744, 3015 => 743, 1407 => 742, 1583 => 741, 1575 => 740, 1484 => 739, 1616 => 738, 1666 => 737, 1515 => 736, 1439 => 735, 1572 => 734, 1406 => 733, 1567 => 732, 1552 => 731, 1665 => 730, 1615 => 729, 1573 => 728, 1488 => 727, 1584 => 726, 1545 => 725, 1491 => 724, 1614 => 723, 1490 => 722, 1625 => 721, 3034 => 720, 3022 => 719, 3029 => 718, 3028 => 717, 1689 => 716, 1659 => 715, 3006 => 714, 3004 => 713, 3078 => 712, 1534 => 711, 3059 => 710, 3025 => 709, 3000 => 708, 3012 => 707, 1676 => 706, 3090 => 705, 3091 => 704, 3126 => 703, 3049 => 702, 1537 => 701, 3124 => 700, 3119 => 699, 3048 => 698, 3046 => 697, 3035 => 696, 3037 => 695, 1520 => 694, 3137 => 693, 3019 => 692, 3062 => 691, 1625 => 690, 1626 => 689, 1627 => 688, 3064 => 687, 1675 => 686, 3105 => 685, 3024 => 684, 3094 => 683, 3087 => 682, 1660 => 681, 3065 => 680, 3084 => 679, 3018 => 678, 3080 => 677, 1694 => 676, 3061 => 675, 3092 => 674, 1667 => 673, 3021 => 672, 1702 => 671, 3017 => 670, 1596 => 669, 1648 => 668, 1698 => 667, 3047 => 666, 1642 => 665, 1654 => 664, 1630 => 663, 3001 => 662, 1693 => 661, 1647 => 660, 1643 => 659, 3045 => 658, 1641 => 657, 3007 => 656, 3043 => 655, 3104 => 654, 1697 => 653, 3089 => 652, 1701 => 651, 1649 => 650, 1652 => 649, 1668 => 648, 1653 => 647, 3038 => 646, 3044 => 645, 1661 => 644, 1629 => 643, 3032 => 642, 1670 => 641, 3081 => 640, 3050 => 639, 3014 => 638, 1691 => 637, 3120 => 636, 3125 => 635, 3129 => 634, 3131 => 633, 3134 => 632, 3135 => 631, 3136 => 630, 3143 => 629, 3146 => 628, 3153 => 627, 3154 => 626, 3155 => 625, 3156 => 624, 3157 => 623, 3158 => 622, 3163 => 621, 3164 => 620, 3167 => 619, 3169 => 618, 3031 => 617, 3077 => 616, 1682 => 615, 3127 => 614, 3150 => 613, 3151 => 612, 3152 => 611, 3162 => 610, 3147 => 609, 1555 => 608, 3139 => 607, 1014 => 606, 1224 => 605, 3159 => 604, 1684 => 603, 3066 => 602, 3100 => 601, 3086 => 600, 3095 => 599, 3060 => 598, 3088 => 597, 1683 => 596, 1680 => 595, 1681 => 594, 1679 => 593, 3098 => 592, 3099 => 591, 3101 => 590, 3103 => 589, 3107 => 588, 3111 => 587, 3112 => 586, 3113 => 585, 3096 => 584, 3097 => 583, 1688 => 582, 3115 => 581, 3116 => 580, 3117 => 579, 3118 => 578, 3132 => 577, 3133 => 576, 3138 => 575, 3140 => 574, 3141 => 573, 3142 => 572, 3144 => 571, 3148 => 570, 3149 => 569, 3161 => 568, 3165 => 567, 3166 => 566 }

  ##
  # Takes an array of integers, arrays, or hashes. If using array or hash, must provide location of ontology virtual id.
  # Options:
  # :position => location in the array (int) or hash key containing the virtual id
  def self.rank(ont_ary, options = {})
    return nil if !ont_ary.kind_of?(Array)
    position = options[:position]

    ranked = []
    not_ranked = []
    ont_ary.each do |ont|
      if position.nil?
        if WEIGHT.key?(ont.to_i)
          ranked << ont
        else
          not_ranked << ont
        end
      else
        if WEIGHT.key?(ont[position].to_i)
          ranked << ont
        else
          not_ranked << ont
        end
      end
    end

    # Sort ontologies
    if position.nil?
      ranked.sort! {|a,b| WEIGHT[b.to_i] <=> WEIGHT[a.to_i]}
    else
      # Get a ranked list of the virtual ids in the ranked set
      ranked.sort! {|a,b| WEIGHT[b[position].to_i] <=> WEIGHT[a[position].to_i]}
    end

    # Recombine the ranked and non-ranked
    ranked.concat not_ranked
  end

  def self.rank!(ont_ary, options = {})
    ont_ary = self.rank(ont_ary, options)
  end

end