//
//  SHA256.swift
//  OAuthSwift
//
//  Created by Matthew Braun on 8/15/19.
//  Copyright © 2019 Dongri Jin. All rights reserved.
//

import Foundation
import CommonCrypto

class SHA256 {
    
    typealias Context = UnsafeMutablePointer<CCHmacContext>
    
    let context = Context.allocate(capacity: 1)
    
    var algorithm: CCHmacAlgorithm
    
    private var message: [UInt8]
    
    init(_ message: Data) {
        self.message = message.bytes
        self.algorithm = CCHmacAlgorithm(kCCHmacAlgSHA256)
        
        CCHmacInit(context, self.algorithm, self.message, size_t(self.message.count))
        
    }
    
    init(_ message: [UInt8]) {
        self.message = message
        self.algorithm = CCHmacAlgorithm(kCCHmacAlgSHA256)
        
        CCHmacInit(context, self.algorithm, self.message, size_t(self.message.count))
    }
    
    func calculate() -> [UInt8] {
        let digestLength = Int(CC_SHA256_DIGEST_LENGTH)
        var hmac = Array<UInt8>(repeating: 0, count: digestLength)
        CCHmacFinal(context, &hmac)
        return hmac
    }
    
    deinit {
        context.deallocate()
    }
}
