import Foundation

public extension Envelope {
    static func parameter(_ param: ParameterIdentifier, value: CBOREncodable?) -> Envelope? {
        guard let value else {
            return nil
        }
        return Envelope(param.cbor, Envelope(value))
    }

    static func parameter(_ name: String, value: CBOREncodable?) -> Envelope? {
        guard let value else {
            return nil
        }
        return parameter(ParameterIdentifier(name), value: value)
    }

    func addParameter(_ param: ParameterIdentifier, value: CBOREncodable?) -> Envelope {
        try! addAssertion(.parameter(param, value: value))
    }

    func addParameter(_ name: String, value: CBOREncodable?) -> Envelope {
        try! addAssertion(.parameter(name, value: value))
    }
    
    func result() throws -> Envelope {
        try extractObject(forPredicate: .result)
    }
    
    func results() throws -> [Envelope] {
        extractObjects(forPredicate: .result)
    }
    
    func result<T: CBORDecodable>(_ type: T.Type) throws -> T {
        try extractObject(T.self, forPredicate: .result)
    }
    
    func results<T: CBORDecodable>(_ type: T.Type) throws -> [T] {
        try extractObjects(T.self, forPredicate: .result)
    }
    
    func isResultOK() throws -> Bool {
        try result(KnownValue.self) == .ok
    }
    
    func error<T: CBORDecodable>(_ type: T.Type) throws -> T {
        try extractObject(T.self, forPredicate: .error)
    }
}

public extension Envelope {
    init(function: FunctionIdentifier) {
        self.init(function)
    }

    init(function name: String) {
        self.init(function: FunctionIdentifier(name))
    }

    init(function value: Int, name: String? = nil) {
        self.init(function: FunctionIdentifier(value, name))
    }

    init(request id: CID, body: CBOREncodable) {
        self = Envelope(CBOR.tagged(.request, id.taggedCBOR))
            .addAssertion(.body, body)
    }

    init(response id: CID, result: CBOREncodable? = KnownValue.ok) {
        self = Envelope(CBOR.tagged(.response, id.taggedCBOR))
            .addAssertion(.result, result)
    }
    
    init(response id: CID, results: [CBOREncodable]) {
        var e = Envelope(CBOR.tagged(.response, id.taggedCBOR))
        for result in results {
            e = e.addAssertion(.result, result)
        }
        self = e
    }
    
    init(response id: CID, error: CBOREncodable) {
        self = Envelope(CBOR.tagged(.response, id.taggedCBOR))
            .addAssertion(.error, error)
    }
    
    init(error: CBOREncodable?) {
        self = Envelope(CBOR.tagged(.response, "unknown"))
            .addAssertion(.error, error)
    }
}
