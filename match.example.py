def match_client(packet):
    return all(word in str(packet.payload) for word in ["transaction", "payment", "acme"])

def match_server(packet):
    return all(word in str(packet.payload) for word in ["acme", "transactionResponse"]);
