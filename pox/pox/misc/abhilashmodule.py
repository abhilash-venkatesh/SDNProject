def reverseDicLookup(dic,query_value):
    for key in dic:
        value = dic[key]
        if value == query_value:
            return key
    return -1
