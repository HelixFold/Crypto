/**
 * Imports
 */

import { decodeHex, encodeHex } from "@hex";
import { Ed25519Error, ed25519PublicKey, ed25519Sign, ed25519Verify } from "@ed25519";

/**
 * Tests
 */

describe("ed25519PublicKey") {
    test("should derive the public keys of RFC 8032 section 7.1") {
        let seed: u8[32] = undefined;
        let out: u8[64] = undefined;

        void try decodeHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", &seed);
        const first = try ed25519PublicKey(&seed);
        const firstText: string = try encodeHex(&first, &out);
        expect(firstText).toBe("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        void try decodeHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", &seed);
        const second = try ed25519PublicKey(&seed);
        const secondText: string = try encodeHex(&second, &out);
        expect(secondText).toBe("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

        void try decodeHex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", &seed);
        const third = try ed25519PublicKey(&seed);
        const thirdText: string = try encodeHex(&third, &out);
        expect(thirdText).toBe("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    }

    test("should reject a seed that is not 32 bytes long") {
        let seed: u8[64] = undefined;
        for (const _, i of seed) seed[i] = 7;
        expect(ed25519PublicKey(seed[0..31])).toThrow(Ed25519Error.BadKeyLength);
        expect(ed25519PublicKey(&seed)).toThrow(Ed25519Error.BadKeyLength);
        expect(ed25519PublicKey("")).toThrow(Ed25519Error.BadKeyLength);
    }
}

describe("ed25519Sign") {
    test("should match RFC 8032 TEST 1, an empty message") {
        let seed: u8[32] = undefined;
        let publicKey: u8[32] = undefined;
        void try decodeHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", &seed);
        void try decodeHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", &publicKey);
        const signature = try ed25519Sign(&seed, "");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&signature, &out);
        expect(text[0..64]).toBe("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155");
        expect(text[64..128]).toBe("5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        expect(ed25519Verify(&publicKey, "", &signature)).toBeTrue();
    }

    test("should match RFC 8032 TEST 2, a one-byte message") {
        let seed: u8[32] = undefined;
        let publicKey: u8[32] = undefined;
        void try decodeHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", &seed);
        void try decodeHex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", &publicKey);
        const signature = try ed25519Sign(&seed, "\x72");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&signature, &out);
        expect(text[0..64]).toBe("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da");
        expect(text[64..128]).toBe("085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        expect(ed25519Verify(&publicKey, "\x72", &signature)).toBeTrue();
    }

    test("should match RFC 8032 TEST 3, a two-byte message") {
        let seed: u8[32] = undefined;
        let publicKey: u8[32] = undefined;
        void try decodeHex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", &seed);
        void try decodeHex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", &publicKey);
        const signature = try ed25519Sign(&seed, "\xaf\x82");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&signature, &out);
        expect(text[0..64]).toBe("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac");
        expect(text[64..128]).toBe("18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
        expect(ed25519Verify(&publicKey, "\xaf\x82", &signature)).toBeTrue();
    }

    test("should match RFC 8032 TEST 1024, a 1023-byte message") {
        let seed: u8[32] = undefined;
        let publicKey: u8[32] = undefined;
        void try decodeHex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5", &seed);
        void try decodeHex("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e", &publicKey);
        let message: u8[1023] = undefined;
        void try decodeHex("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98", message[0..32]);
        void try decodeHex("fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8", message[32..64]);
        void try decodeHex("79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d", message[64..96]);
        void try decodeHex("658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc", message[96..128]);
        void try decodeHex("1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe", message[128..160]);
        void try decodeHex("ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e", message[160..192]);
        void try decodeHex("06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef", message[192..224]);
        void try decodeHex("efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7", message[224..256]);
        void try decodeHex("aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1", message[256..288]);
        void try decodeHex("85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2", message[288..320]);
        void try decodeHex("d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24", message[320..352]);
        void try decodeHex("554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270", message[352..384]);
        void try decodeHex("88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc", message[384..416]);
        void try decodeHex("2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07", message[416..448]);
        void try decodeHex("07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba", message[448..480]);
        void try decodeHex("b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a", message[480..512]);
        void try decodeHex("ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e", message[512..544]);
        void try decodeHex("c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7", message[544..576]);
        void try decodeHex("51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c", message[576..608]);
        void try decodeHex("42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8", message[608..640]);
        void try decodeHex("ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df", message[640..672]);
        void try decodeHex("f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08", message[672..704]);
        void try decodeHex("d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649", message[704..736]);
        void try decodeHex("de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4", message[736..768]);
        void try decodeHex("88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3", message[768..800]);
        void try decodeHex("2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e", message[800..832]);
        void try decodeHex("6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f", message[832..864]);
        void try decodeHex("b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5", message[864..896]);
        void try decodeHex("0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1", message[896..928]);
        void try decodeHex("369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d", message[928..960]);
        void try decodeHex("b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c", message[960..992]);
        void try decodeHex("0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0", message[992..1023]);
        const derived = try ed25519PublicKey(&seed);
        let keyOut: u8[64] = undefined;
        const keyText: string = try encodeHex(&derived, &keyOut);
        expect(keyText).toBe("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");

        const signature = try ed25519Sign(&seed, &message);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&signature, &out);
        expect(text[0..64]).toBe("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350");
        expect(text[64..128]).toBe("aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");
        expect(ed25519Verify(&publicKey, &message, &signature)).toBeTrue();
        message[1022] ^= 1;
        expect(ed25519Verify(&publicKey, &message, &signature)).toBeFalse();
    }

    test("should give the same signature every time") {
        let seed: u8[32] = undefined;
        for (const _, i of seed) seed[i] = i as u8;
        const first = try ed25519Sign(&seed, "message");
        const second = try ed25519Sign(&seed, "message");
        for (const byte, i of first) expect(byte).toBe(second[i]);
    }

    test("should reject a seed that is not 32 bytes long") {
        let seed: u8[33] = undefined;
        for (const _, i of seed) seed[i] = 7;
        expect(ed25519Sign(&seed, "message")).toThrow(Ed25519Error.BadKeyLength);
        expect(ed25519Sign(seed[0..31], "message")).toThrow(Ed25519Error.BadKeyLength);
    }
}

describe("ed25519Verify") {
    test("should reject a signature with a flipped bit in R or in S") {
        let publicKey: u8[32] = undefined;
        let signature: u8[64] = undefined;
        void try decodeHex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", &publicKey);
        void try decodeHex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac", signature[0..32]);
        void try decodeHex("18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", signature[32..64]);
        expect(ed25519Verify(&publicKey, "\xaf\x82", &signature)).toBeTrue();
        signature[0] ^= 1;
        expect(ed25519Verify(&publicKey, "\xaf\x82", &signature)).toBeFalse();
        signature[0] ^= 1;
        signature[40] ^= 1;
        expect(ed25519Verify(&publicKey, "\xaf\x82", &signature)).toBeFalse();
    }

    test("should reject a wrong message") {
        let publicKey: u8[32] = undefined;
        let signature: u8[64] = undefined;
        void try decodeHex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", &publicKey);
        void try decodeHex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac", signature[0..32]);
        void try decodeHex("18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", signature[32..64]);
        expect(ed25519Verify(&publicKey, "\xaf\x83", &signature)).toBeFalse();
        expect(ed25519Verify(&publicKey, "\xaf", &signature)).toBeFalse();
        expect(ed25519Verify(&publicKey, "", &signature)).toBeFalse();
    }

    test("should reject an S of L or more, even when S minus L would verify") {
        let publicKey: u8[32] = undefined;
        let signature: u8[64] = undefined;
        void try decodeHex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", &publicKey);
        void try decodeHex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac", signature[0..32]);
        void try decodeHex("05d391b0a77904e98404ef037747a56e4a7c15e9716ed28dc027beceea1ec41a", signature[32..64]);
        expect(ed25519Verify(&publicKey, "\xaf\x82", &signature)).toBeFalse();
        for (const i of 32..64) signature[i] = 0xFF;
        expect(ed25519Verify(&publicKey, "\xaf\x82", &signature)).toBeFalse();
    }

    test("should reject a public key that doesn't decode") {
        let signature: u8[64] = undefined;
        void try decodeHex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac", signature[0..32]);
        void try decodeHex("18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", signature[32..64]);
        let publicKey: u8[32] = undefined;

        void try decodeHex("0200000000000000000000000000000000000000000000000000000000000000", &publicKey);
        expect(ed25519Verify(&publicKey, "\xaf\x82", &signature)).toBeFalse();
        void try decodeHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", &publicKey);
        expect(ed25519Verify(&publicKey, "\xaf\x82", &signature)).toBeFalse();
        void try decodeHex("0100000000000000000000000000000000000000000000000000000000000080", &publicKey);
        expect(ed25519Verify(&publicKey, "\xaf\x82", &signature)).toBeFalse();
    }

    test("should reject a public key or signature of the wrong length") {
        let publicKey: u8[32] = undefined;
        let signature: u8[64] = undefined;
        void try decodeHex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", &publicKey);
        void try decodeHex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac", signature[0..32]);
        void try decodeHex("18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", signature[32..64]);
        expect(ed25519Verify(publicKey[0..31], "\xaf\x82", &signature)).toBeFalse();
        expect(ed25519Verify(&publicKey, "\xaf\x82", signature[0..63])).toBeFalse();
        expect(ed25519Verify("", "\xaf\x82", "")).toBeFalse();
    }

    test("should accept its own signatures over many messages") {
        let seed: u8[32] = undefined;
        for (const _, i of seed) seed[i] = (i * 7) as u8;
        const publicKey = try ed25519PublicKey(&seed);
        let message: u8[40] = undefined;
        for (const n of 0..40) {
            message[n] = n as u8;
            const signature = try ed25519Sign(&seed, message[0..n + 1]);
            expect(ed25519Verify(&publicKey, message[0..n + 1], &signature)).toBeTrue();
        }
    }
}
