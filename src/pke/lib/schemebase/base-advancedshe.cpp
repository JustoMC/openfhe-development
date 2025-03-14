//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================
#include "schemebase/base-advancedshe.h"

#include "key/privatekey.h"
#include "cryptocontext.h"
#include "schemebase/base-scheme.h"

namespace lbcrypto {

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalAddMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const {
    const size_t inSize = ciphertextVec.size();

    if (ciphertextVec.size() < 1)
        OPENFHE_THROW("Input ciphertext vector size should be 1 or more");

    const size_t lim = inSize * 2 - 2;
    std::vector<Ciphertext<Element>> ciphertextSumVec;
    ciphertextSumVec.resize(inSize - 1);
    size_t ctrIndex = 0;

    auto algo = ciphertextVec[0]->GetCryptoContext()->GetScheme();

    for (size_t i = 0; i < lim; i = i + 2) {
        ciphertextSumVec[ctrIndex++] =
            algo->EvalAdd(i < inSize ? ciphertextVec[i] : ciphertextSumVec[i - inSize],
                          i + 1 < inSize ? ciphertextVec[i + 1] : ciphertextSumVec[i + 1 - inSize]);
    }

    return ciphertextSumVec.back();
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalAddManyInPlace(
    std::vector<Ciphertext<Element>>& ciphertextVec) const {
    if (ciphertextVec.size() < 1)
        OPENFHE_THROW("Input ciphertext vector size should be 1 or more");

    auto algo = ciphertextVec[0]->GetCryptoContext()->GetScheme();

    for (size_t j = 1; j < ciphertextVec.size(); j = j * 2) {
        for (size_t i = 0; i < ciphertextVec.size(); i = i + 2 * j) {
            if ((i + j) < ciphertextVec.size()) {
                if (ciphertextVec[i] != nullptr && ciphertextVec[i + j] != nullptr) {
                    ciphertextVec[i] = algo->EvalAdd(ciphertextVec[i], ciphertextVec[i + j]);
                }
                else if (ciphertextVec[i] == nullptr && ciphertextVec[i + j] != nullptr) {
                    ciphertextVec[i] = ciphertextVec[i + j];
                }
            }
        }
    }

    Ciphertext<Element> result(std::make_shared<CiphertextImpl<Element>>(*(ciphertextVec[0])));

    return result;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalMultMany(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                           const std::vector<EvalKey<Element>>& evalKeys) const {
    if (ciphertextVec.size() < 1)
        OPENFHE_THROW("Input ciphertext vector size should be 1 or more");

    const size_t inSize = ciphertextVec.size();
    const size_t lim    = inSize * 2 - 2;
    std::vector<Ciphertext<Element>> ciphertextMultVec;
    ciphertextMultVec.resize(inSize - 1);
    size_t ctrIndex = 0;

    auto algo = ciphertextVec[0]->GetCryptoContext()->GetScheme();

    for (size_t i = 0; i < lim; i = i + 2) {
        ciphertextMultVec[ctrIndex] = algo->EvalMultAndRelinearize(
            i < inSize ? ciphertextVec[i] : ciphertextMultVec[i - inSize],
            i + 1 < inSize ? ciphertextVec[i + 1] : ciphertextMultVec[i + 1 - inSize], evalKeys);
        algo->ModReduceInPlace(ciphertextMultVec[ctrIndex++], 1);
    }

    return ciphertextMultVec.back();
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::AddRandomNoise(ConstCiphertext<Element> ciphertext) const {
    if (!ciphertext)
        OPENFHE_THROW("Input ciphertext is nullptr");

    std::uniform_real_distribution<double> distribution(0.0, 1.0);

    std::string kID           = ciphertext->GetKeyTag();
    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams  = cryptoParams->GetElementParams();

    usint n = elementParams->GetRingDimension();

    auto cc = ciphertext->GetCryptoContext();

    Plaintext plaintext;

    if (ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) {
        std::vector<std::complex<double>> randomIntVector(n);

        // first plaintext slot does not need to change
        randomIntVector[0].real(0);

        for (usint i = 0; i < n - 1; i++) {
            randomIntVector[i + 1].real(distribution(PseudoRandomNumberGenerator::GetPRNG()));
        }

        plaintext = cc->MakeCKKSPackedPlaintext(randomIntVector, ciphertext->GetNoiseScaleDeg(), 0, nullptr,
                                                ciphertext->GetSlots());
    }
    else {
        DiscreteUniformGeneratorImpl<typename Element::Vector> dug;
        auto randomVector{dug.GenerateVector(n - 1, encodingParams->GetPlaintextModulus())};

        std::vector<int64_t> randomIntVector(n);

        // first plaintext slot does not need to change
        randomIntVector[0] = 0;

        for (usint i = 0; i < n - 1; i++) {
            randomIntVector[i + 1] = randomVector[i].ConvertToInt();
        }

        plaintext = cc->MakePackedPlaintext(randomIntVector);
    }

    plaintext->Encode();
    plaintext->GetElement<Element>().SetFormat(EVALUATION);
    auto algo = cc->GetScheme();
    return algo->EvalAdd(ciphertext, plaintext);
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> AdvancedSHEBase<Element>::EvalSumKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) const {
    if (!privateKey)
        OPENFHE_THROW("Input private key is nullptr");
    /*
   * we don't validate publicKey as it is needed by NTRU-based scheme only
   * NTRU-based scheme only and it is checked for null later.
   */

    // get automorphism indices and convert them to a vector
    std::set<uint32_t> indx_set{GenerateIndexListForEvalSum(privateKey)};
    std::vector<uint32_t> indices(indx_set.begin(), indx_set.end());

    auto algo = privateKey->GetCryptoContext()->GetScheme();
    return algo->EvalAutomorphismKeyGen(privateKey, indices);
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> AdvancedSHEBase<Element>::EvalSumRowsKeyGen(
    const PrivateKey<Element> privateKey, usint rowSize, usint subringDim, std::vector<usint>& indices) const {
    auto cc = privateKey->GetCryptoContext();

    if (!isCKKS(cc->getSchemeId()))
        OPENFHE_THROW("Matrix summation of row-vectors is only supported for CKKSPackedEncoding.");

    usint m =
        (subringDim == 0) ? privateKey->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() : subringDim;

    if (!IsPowerOfTwo(m))
        OPENFHE_THROW("Matrix summation of row-vectors is not supported for arbitrary cyclotomics.");

    std::set<uint32_t> rowsIndices{GenerateIndices2nComplexRows(rowSize, m)};
    indices.reserve(indices.size() + rowsIndices.size());
    indices.insert(indices.end(), rowsIndices.begin(), rowsIndices.end());

    auto algo = cc->GetScheme();
    return algo->EvalAutomorphismKeyGen(privateKey, indices);
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> AdvancedSHEBase<Element>::EvalSumColsKeyGen(
    const PrivateKey<Element> privateKey, std::vector<usint>& indices) const {
    auto cc = privateKey->GetCryptoContext();

    if (!isCKKS(cc->getSchemeId()))
        OPENFHE_THROW("Matrix summation of column-vectors is only supported for CKKSPackedEncoding.");

    const auto cryptoParams = privateKey->GetCryptoParameters();
    usint M                 = cryptoParams->GetElementParams()->GetCyclotomicOrder();
    if (!IsPowerOfTwo(M))
        OPENFHE_THROW("Matrix summation of column-vectors is not supported for arbitrary cyclotomics.");

    usint batchSize = cryptoParams->GetEncodingParams()->GetBatchSize();

    // get indices for EvalSumCols() and merge them with the indices for EvalSum()
    std::set<uint32_t> evalSumColsIndices = GenerateIndices2nComplexCols(batchSize, M);
    std::set<uint32_t> evalSumIndices     = GenerateIndexListForEvalSum(privateKey);
    evalSumColsIndices.merge(evalSumIndices);
    indices.reserve(indices.size() + evalSumColsIndices.size());
    indices.insert(indices.end(), evalSumColsIndices.begin(), evalSumColsIndices.end());

    auto algo = cc->GetScheme();
    return algo->EvalAutomorphismKeyGen(privateKey, indices);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize,
                                                      const std::map<usint, EvalKey<Element>>& evalKeyMap) const {
    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();

    if ((encodingParams->GetBatchSize() == 0))
        OPENFHE_THROW(
            "EvalSum: Packed encoding parameters 'batch size' is not set; "
            "Please check the EncodingParams passed to the crypto context.");

    usint m = cryptoParams->GetElementParams()->GetCyclotomicOrder();

    Ciphertext<Element> newCiphertext = ciphertext->Clone();

    if (IsPowerOfTwo(m)) {
        if (ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING)
            newCiphertext = EvalSum2nComplex(newCiphertext, batchSize, m, evalKeyMap);
        else
            newCiphertext = EvalSum_2n(newCiphertext, batchSize, m, evalKeyMap);
    }
    else {  // Arbitrary cyclotomics
        if (encodingParams->GetPlaintextGenerator() == 0) {
            OPENFHE_THROW(
                "EvalSum: Packed encoding parameters 'plaintext "
                "generator' is not set; Please check the "
                "EncodingParams passed to the crypto context.");
        }
        else {
            auto algo = ciphertext->GetCryptoContext()->GetScheme();

            usint g = encodingParams->GetPlaintextGenerator();
            for (int i = 0; i < floor(log2(batchSize)); i++) {
                auto ea       = algo->EvalAutomorphism(newCiphertext, g, evalKeyMap);
                newCiphertext = algo->EvalAdd(newCiphertext, ea);
                g             = (g * g) % m;
            }
        }
    }

    return newCiphertext;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSumRows(ConstCiphertext<Element> ciphertext, uint32_t numRows,
                                                          const std::map<uint32_t, EvalKey<Element>>& evalSumKeys,
                                                          uint32_t subringDim) const {
    if (ciphertext->GetEncodingType() != CKKS_PACKED_ENCODING)
        OPENFHE_THROW("Matrix summation of row-vectors is only supported for CKKS packed encoding.");

    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    if ((encodingParams->GetBatchSize() == 0))
        OPENFHE_THROW(
            "Packed encoding parameters 'batch size' is not set. Please check the EncodingParams passed to the crypto context.");

    uint32_t m = (subringDim == 0) ? cryptoParams->GetElementParams()->GetCyclotomicOrder() : subringDim;
    if (!IsPowerOfTwo(m))
        OPENFHE_THROW("Matrix summation of row-vectors is not supported for arbitrary cyclotomics.");

    return EvalSum2nComplexRows(ciphertext->Clone(), numRows, m, evalSumKeys);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSumCols(
    ConstCiphertext<Element> ciphertext, uint32_t numCols, const std::map<uint32_t, EvalKey<Element>>& evalSumKeyMap,
    const std::map<uint32_t, EvalKey<Element>>& evalSumColsKeyMap) const {
    if (!ciphertext)
        OPENFHE_THROW("Input ciphertext is nullptr");
    if (!evalSumKeyMap.size())
        OPENFHE_THROW("Input evalKeys map is empty");
    if (!evalSumColsKeyMap.size())
        OPENFHE_THROW("Input rightEvalKeys map is empty");
    if (ciphertext->GetEncodingType() != CKKS_PACKED_ENCODING)
        OPENFHE_THROW("Matrix summation of column-vectors is only supported for CKKS packed encoding.");

    const uint32_t slots = ciphertext->GetSlots();
    if (slots < numCols)
        OPENFHE_THROW("The number of columns ca not be greater than the number of slots.");

    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    if ((encodingParams->GetBatchSize() == 0))
        OPENFHE_THROW(
            "Packed encoding parameters 'batch size' is not set. Please check the EncodingParams passed to the crypto context.");

    const auto elementParams = cryptoParams->GetElementParams();
    uint32_t m               = elementParams->GetCyclotomicOrder();
    if (!IsPowerOfTwo(m))
        OPENFHE_THROW("Matrix summation of column-vectors is not supported for arbitrary cyclotomics.");

    std::vector<std::complex<double>> mask(slots, 0);  // create a mask vector and set all its elements to zero
    for (size_t i = 0; i < mask.size(); i++) {
        if (i % numCols == 0)
            mask[i] = 1;
    }

    Ciphertext<Element> newCiphertext = EvalSum2nComplex(ciphertext->Clone(), numCols, m, evalSumKeyMap);
    auto cc                           = ciphertext->GetCryptoContext();
    auto algo                         = cc->GetScheme();
    Plaintext plaintext               = cc->MakeCKKSPackedPlaintext(mask, 1, 0, nullptr, slots);
    algo->EvalMultInPlace(newCiphertext, plaintext);

    return EvalSum2nComplexCols(newCiphertext, numCols, m, evalSumColsKeyMap);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
                                                               ConstCiphertext<Element> ciphertext2, usint batchSize,
                                                               const std::map<usint, EvalKey<Element>>& evalSumKeyMap,
                                                               const EvalKey<Element> evalMultKey) const {
    auto algo = ciphertext1->GetCryptoContext()->GetScheme();

    Ciphertext<Element> result = algo->EvalMult(ciphertext1, ciphertext2, evalMultKey);

    result = EvalSum(result, batchSize, evalSumKeyMap);

    // add a random number to all slots except for the first one so that no
    // information is leaked
    // if (ciphertext1->GetEncodingType() != CKKS_PACKED_ENCODING)
    //   result = AddRandomNoise(result);
    return result;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalInnerProduct(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext, usint batchSize,
    const std::map<usint, EvalKey<Element>>& evalSumKeyMap) const {
    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    Ciphertext<Element> result = algo->EvalMult(ciphertext, plaintext);

    result = EvalSum(result, batchSize, evalSumKeyMap);

    // add a random number to all slots except for the first one so that no
    // information is leaked
    // if (ciphertext1->GetEncodingType() != CKKS_PACKED_ENCODING)
    //   result = AddRandomNoise(result);
    return result;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalMerge(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                        const std::map<usint, EvalKey<Element>>& evalKeyMap) const {
    if (ciphertextVec.size() == 0)
        OPENFHE_THROW("the vector of ciphertexts to be merged cannot be empty");

    const std::shared_ptr<CryptoParametersBase<Element>> cryptoParams = ciphertextVec[0]->GetCryptoParameters();
    Ciphertext<Element> ciphertextMerged(std::make_shared<CiphertextImpl<Element>>(*(ciphertextVec[0])));

    auto cc = ciphertextVec[0]->GetCryptoContext();

    Plaintext plaintext;
    if (ciphertextVec[0]->GetEncodingType() == CKKS_PACKED_ENCODING) {
        std::vector<std::complex<double>> mask({{1, 0}, {0, 0}});
        plaintext = cc->MakeCKKSPackedPlaintext(mask, 1, 0, nullptr, ciphertextVec[0]->GetSlots());
    }
    else {
        std::vector<int64_t> mask = {1, 0};
        plaintext                 = cc->MakePackedPlaintext(mask);
    }
    auto algo = ciphertextVec[0]->GetCryptoContext()->GetScheme();

    ciphertextMerged = algo->EvalMult(ciphertextMerged, plaintext);

    for (size_t i = 1; i < ciphertextVec.size(); i++) {
        ciphertextMerged = algo->EvalAdd(
            ciphertextMerged, algo->EvalAtIndex(algo->EvalMult(ciphertextVec[i], plaintext), -(int32_t)i, evalKeyMap));
    }

    return ciphertextMerged;
}

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateIndices_2n(usint batchSize, usint m) const {
    std::set<uint32_t> indices;
    if (batchSize > 1) {
        auto isize = static_cast<size_t>(std::ceil(std::log2(batchSize)) - 1);
        usint g    = 5;
        for (size_t i = 0; i < isize; ++i) {
            indices.insert(g);
            g = (g * g) % m;
        }
        if (2 * batchSize < m)
            indices.insert(g);
        else
            indices.insert(m - 1);
    }

    return indices;
}

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateIndices2nComplex(usint batchSize, usint m) const {
    auto isize = static_cast<size_t>(std::ceil(std::log2(batchSize)));

    std::set<uint32_t> indices;
    uint32_t g = 5;
    for (size_t i = 0; i < isize; ++i) {
        indices.insert(g);
        g = (g * g) % m;
    }

    return indices;
}

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateIndices2nComplexRows(usint rowSize, usint m) const {
    uint32_t colSize = m / (4 * rowSize);
    auto isize       = static_cast<size_t>(std::ceil(std::log2(colSize)));

    std::set<uint32_t> indices;
    uint32_t g = (NativeInteger(5).ModExp(rowSize, m)).ConvertToInt<uint32_t>();
    for (size_t i = 0; i < isize; ++i) {
        indices.insert(g);
        g = (g * g) % m;
    }

    return indices;
}

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateIndices2nComplexCols(usint batchSize, usint m) const {
    auto isize = static_cast<size_t>(std::ceil(std::log2(batchSize)));

    std::set<uint32_t> indices;
    uint32_t g = NativeInteger(5).ModInverse(m).ConvertToInt<uint32_t>();
    for (size_t i = 0; i < isize; ++i) {
        indices.insert(g);
        g = (g * g) % m;
    }

    return indices;
}

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateIndexListForEvalSum(const PrivateKey<Element>& privateKey) const {
    const auto cryptoParams   = privateKey->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams  = cryptoParams->GetElementParams();

    uint32_t batchSize = encodingParams->GetBatchSize();
    uint32_t m         = elementParams->GetCyclotomicOrder();

    std::set<uint32_t> indices;
    if (IsPowerOfTwo(m)) {
        auto ccInst = privateKey->GetCryptoContext();
        // CKKS Packing
        indices =
            isCKKS(ccInst->getSchemeId()) ? GenerateIndices2nComplex(batchSize, m) : GenerateIndices_2n(batchSize, m);
    }
    else {
        // Arbitrary cyclotomics
        auto isize = static_cast<size_t>(std::floor(std::log2(batchSize)));
        uint32_t g = encodingParams->GetPlaintextGenerator();
        for (size_t i = 0; i < isize; i++) {
            indices.insert(g);
            g = (g * g) % m;
        }
    }

    return indices;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum_2n(ConstCiphertext<Element> ciphertext, uint32_t batchSize,
                                                         uint32_t m,
                                                         const std::map<uint32_t, EvalKey<Element>>& evalKeys) const {
    Ciphertext<Element> newCiphertext(std::make_shared<CiphertextImpl<Element>>(*ciphertext));
    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    if (batchSize > 1) {
        uint32_t g = 5;
        for (size_t i = 0; i < static_cast<size_t>(std::ceil(std::log2(batchSize))) - 1; ++i) {
            newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, g, evalKeys));
            g             = (g * g) % m;
        }
        if (2 * batchSize < m)
            newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, g, evalKeys));
        else
            newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, m - 1, evalKeys));
    }

    return newCiphertext;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum2nComplex(
    ConstCiphertext<Element> ciphertext, usint batchSize, usint m,
    const std::map<usint, EvalKey<Element>>& evalKeys) const {
    Ciphertext<Element> newCiphertext(std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    uint32_t g = 5;
    auto algo  = ciphertext->GetCryptoContext()->GetScheme();

    for (size_t i = 0; i < static_cast<size_t>(std::ceil(std::log2(batchSize))); ++i) {
        newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, g, evalKeys));
        g             = (g * g) % m;
    }

    return newCiphertext;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum2nComplexRows(
    ConstCiphertext<Element> ciphertext, usint rowSize, usint m,
    const std::map<usint, EvalKey<Element>>& evalKeys) const {
    Ciphertext<Element> newCiphertext(std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    uint32_t colSize = m / (4 * rowSize);
    uint32_t g       = (NativeInteger(5).ModExp(rowSize, m)).ConvertToInt<uint32_t>();
    auto algo        = ciphertext->GetCryptoContext()->GetScheme();

    for (size_t i = 0; i < static_cast<size_t>(std::ceil(std::log2(colSize))); ++i) {
        newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, g, evalKeys));
        g             = (g * g) % m;
    }

    return newCiphertext;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum2nComplexCols(
    ConstCiphertext<Element> ciphertext, usint batchSize, usint m,
    const std::map<usint, EvalKey<Element>>& evalKeys) const {
    Ciphertext<Element> newCiphertext(std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    uint32_t g = NativeInteger(5).ModInverse(m).ConvertToInt<uint32_t>();
    auto algo  = ciphertext->GetCryptoContext()->GetScheme();

    for (size_t i = 0; i < static_cast<size_t>(std::ceil(std::log2(batchSize))); ++i) {
        newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, g, evalKeys));
        g             = (g * g) % m;
    }

    return newCiphertext;
}

//------------------------------------------------------------------------------
// MATRIX MULTIPLICATION
//------------------------------------------------------------------------------
#define debug false
#define reduceRotation true
#define reduceRotationNegative true

std::set<int> RotationReduce(int rot, usint slots) {
    rot = rot % slots;
    if (rot==0)
        return {};
    int tam = (int)ceil(log2(slots));
    std::set<int> ret;
#if reduceRotationNegative
    int r=0;
    for (int i=rot; i>0; i>>=1)
        if (i & 1)
            r++;
    if (r > tam/2)
        rot = rot-slots;
    if (rot < 0) {
        for (int i=0; i<tam; i++)
            if (-rot & (1<<i))
                ret.insert(-(1<<i));
    } else
#endif
    for (int i=0; i<tam; i++)
        if (rot & (1<<i))
            ret.insert((1<<i));
    return ret;
}

std::set<int> RotationsReduce(std::set<int> rotations, usint slots) {
    std::set<int> ret;
    for (int rot : rotations)
        for (int i : RotationReduce(rot, slots))
            ret.insert(i);
    return ret;
}

int RotationQuadrantStrassen(usint quadrantOrig, usint quadrantDest, usint lado, usint lvlStrassen=0) {
    if (quadrantOrig == quadrantDest) {
        return 0;
    } else {
        usint quadMin = std::min(quadrantOrig, quadrantDest),
              quadMax = std::max(quadrantOrig, quadrantDest);
        int ret=lado/(1<<(lvlStrassen+1));
        switch (quadMin^quadMax) {
            case 2:
                ret*=lado;
                break;
            case 3:
                ret*=lado+(quadMin==1 ? -1 : 1);
                break;
        }
        if (quadrantDest>quadrantOrig)
            ret = -ret;
        return ret;
    }
}

std::set<int> RotationsHEMatrixMultiplication(usint lado, usint lvlStrassen=0) {
    #if debug
    printf("RotationsHEMatrixMultiplication(%d, %d)\n", lado, lvlStrassen);
    #endif
    int ladoStr = (lado/(1 << lvlStrassen));
    std::set<int> ret;
    for (int i=1; i<ladoStr; i++) {
        ret.insert(i-ladoStr);
        ret.insert(i);
        ret.insert(i*ladoStr);
    }
    #if reduceRotation
    ret = RotationsReduce(ret, pow(lado, 2));
    #endif
    return ret;
}

std::set<int> RotationsLessMatrixMultiplication(usint lado, usint lvlStrassen=0) {
    #if debug
    printf("RotationsLessMatrixMultiplication(%d, %d)\n", lado, lvlStrassen);
    #endif
    int ladoStr = lado/(1 << lvlStrassen),
        l=log2(lado/ladoStr);
    std::set<int> ret;
    for (int i=1; i<ladoStr; i++) {
        ret.insert(-((i*ladoStr)%lado+i*(pow(ladoStr, 2)-1)));
        ret.insert(-((i*ladoStr)%lado+i*(pow(ladoStr, 2)-lado)));
    }
    for (int i=0; i<log2(ladoStr); i++) {
        ret.insert(-(1 << i));
        ret.insert(-(1 << i)*lado);
        if (pow(lado, 3) <= pow(lado, 2))
            ret.insert(pow(lado, i/l)*(i%l+1)*ladoStr);
    }
    #if reduceRotation
    ret = RotationsReduce(ret, std::max(pow(lado/(1<<lvlStrassen), 3), pow(lado, 2)));
    #endif
    return ret;
}

std::set<int> RotationsStrassen(usint lado, usint strassenAtSize=1,
        MatrixMultiplicationTechnique mmTech=MatrixMultiplicationTechnique::INVALID_MATRIX_MULTIPLICATION_TECHNIQUE,
        usint lvlStrassen=0) {
    #if debug
    printf("RotationsStrassen(%d, %d, %d, %d)\n", lado, strassenAtSize, mmTech, lvlStrassen);
    #endif
    if (lado/(1 << lvlStrassen) <= strassenAtSize) {
        if (strassenAtSize <= 1) {
            return {};
        } else {
            switch (mmTech) {
                case MatrixMultiplicationTechnique::HE_MATRIX_MULTIPLICATION:
                    return RotationsHEMatrixMultiplication(lado, lvlStrassen);
                case MatrixMultiplicationTechnique::LESS_MULTIPLICATIONS_MATRIX_MULTIPLICATION:
                    return RotationsLessMatrixMultiplication(lado, lvlStrassen);
                default:
                    OPENFHE_THROW("Invalid MatrixMultiplicationTechnique");
            }
        }
    } else {
        std::set<int> ret = {
            RotationQuadrantStrassen(1, 0, lado, lvlStrassen),
            RotationQuadrantStrassen(2, 0, lado, lvlStrassen),
            RotationQuadrantStrassen(3, 0, lado, lvlStrassen),
            RotationQuadrantStrassen(0, 1, lado, lvlStrassen),
            RotationQuadrantStrassen(0, 2, lado, lvlStrassen),
            RotationQuadrantStrassen(0, 3, lado, lvlStrassen),
        };
        #if reduceRotation
        ret = RotationsReduce(ret, pow(lado, 2));
        #endif
        for (int i : RotationsStrassen(lado, strassenAtSize, mmTech, lvlStrassen+1))
            ret.insert(i);
        return ret;
    }
}

template <class Element>
void AdvancedSHEBase<Element>::EvalMatrixMultKeyGen(
        const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey,
        MatrixMultiplicationTechnique mmTech, usint strassenAtSize,
        usint rowSize1, usint colSize2, usint rowcolSize) const {
    #if debug
    printf("EvalMatrixMultKeyGen(%s, %s, %d, %d, %d, %d, %d)\n",
            privateKey->GetKeyTag().c_str(), publicKey != nullptr ? publicKey->GetKeyTag().c_str() : "nullptr",
            mmTech, strassenAtSize, rowSize1, colSize2, rowcolSize);
    #endif
    auto cc = privateKey->GetCryptoContext();
    auto batchSize = cc->GetEncodingParams()->GetBatchSize();
    if (rowSize1 == 0 && colSize2 == 0 && rowcolSize == 0) {
        if (sqrt(batchSize) != floor(sqrt(batchSize)))
            OPENFHE_THROW("the dimensions of the matrices must be specified");
        rowSize1 = colSize2 = rowcolSize = (uint)sqrt(batchSize);
    } else if (rowSize1 == 0 || colSize2 == 0 || rowcolSize == 0) {
        OPENFHE_THROW("the dimensions of the matrices must be specified");
    } else if (strassenAtSize != 0 && !(rowSize1 == colSize2 && rowSize1 == rowcolSize) && log2(rowSize1) != floor(log2(rowSize1))) {
        OPENFHE_THROW("the matrices must be square and with sides power of 2 for Strassen's algorithm");
    }
    if (rowcolSize != 1 || !(rowSize1 == 1 || colSize2 == 1)) {
        usint slots = rowcolSize*rowcolSize;
        if (slots > cc->GetRingDimension()/2)
            OPENFHE_THROW("the resulting matrix is too large to be encoded in this context");
        std::set<int> rotations;
        if (strassenAtSize==1) {
            rotations = RotationsStrassen(rowSize1);
        } else {
            if (mmTech == MatrixMultiplicationTechnique::LESS_MULTIPLICATIONS_MATRIX_MULTIPLICATION &&
                    strassenAtSize==0 && cc->GetRingDimension()/2 < pow(rowcolSize, 3))
                strassenAtSize = (1 << (int)(floor(log2(cbrt(cc->GetRingDimension()/2)))));
            if (strassenAtSize==0) {
                switch (mmTech) {
                    case MatrixMultiplicationTechnique::HE_MATRIX_MULTIPLICATION:
                        rotations = RotationsHEMatrixMultiplication(rowSize1);
                        break;
                    case MatrixMultiplicationTechnique::LESS_MULTIPLICATIONS_MATRIX_MULTIPLICATION:
                        rotations = RotationsLessMatrixMultiplication(rowSize1);
                        break;
                    default:
                        OPENFHE_THROW("Invalid MatrixMultiplicationTechnique");
                }
            } else {
                rotations = RotationsStrassen(rowSize1, strassenAtSize, mmTech);
            }
        }
        #if debug
                printf("rotations: ");
                for (int r : rotations)
                    printf("%d, ", r);
                printf("\n");
        #endif
        std::vector<int> rots(rotations.begin(), rotations.end());
        cc->EvalRotateKeyGen(privateKey, rots);
    }
}

template <class Element>
Ciphertext<Element> EvalMultVect(Ciphertext<Element> ct, std::vector<double> v) {
    auto cc = ct->GetCryptoContext();
    return cc->EvalMult(ct, cc->MakeCKKSPackedPlaintext(v, ct->GetNoiseScaleDeg(), 0, nullptr, ct->GetSlots()));
}

std::vector<double> vec_from_pred(uint n, std::function<bool(uint)> pred) {
    std::vector<double> vec = std::vector<double>(n, 0);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (uint i = 0; i < n; i++)
        if (pred(i))
            vec[i] = 1;
    return vec;
}

template <class Element>
Ciphertext<Element> EvalRotateOpt(Ciphertext<Element> ct, int rot) {
    if (rot == 0)
        return ct;
#if reduceRotation
    auto cc = ct->GetCryptoContext();
    for (int i : RotationReduce(rot, ct->GetSlots()))
        ct = cc->EvalRotate(ct, i);
    return ct;
#else
    return ct->GetCryptoContext()->EvalRotate(ct, rot);
#endif
}

template <class Element>
Ciphertext<Element> HEMatMult(Ciphertext<Element> ct1,
                              Ciphertext<Element> ct2,
                              int lado, usint lvlStrassen=0) {
    if (lvlStrassen > 0)
        OPENFHE_THROW("HEMatMult does not support Strassen's algorithm");
    auto cc = ct1->GetCryptoContext();
    uint nElem = lado*lado;
    std::vector<Ciphertext<Element>> v_ctA0 = std::vector<Ciphertext<Element>>(2*lado-1),
                                     v_ctB0 = std::vector<Ciphertext<Element>>(lado),
                                     v_ctAB = std::vector<Ciphertext<Element>>(lado);

    // Step 1-1 ctA0
#if debug
    printf("ctA0: START - Step 1-1 ctA0\n");
#endif
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(2*lado-1))
    for (int k=-lado+1; k<lado; k++){
        v_ctA0[k+lado-1]=EvalMultVect(EvalRotateOpt(ct1, k), vec_from_pred(nElem, [lado, k](int ell){return (k>=0) ? ((unsigned)(ell-lado*k) < (lado-k)) : ((unsigned)(ell-(lado+k)*lado+k) < (lado+k));}));
#if debug
        printf("ctA0: %d/%d\n", k+lado-1, 2*lado-1);
#endif
    }
#if debug
    printf("ctA0: SumMany\n");
#endif
    Ciphertext<Element> ctA0 = cc->EvalAddMany(v_ctA0);
#if debug
    printf("ctA0: END - Step 1-1\n");
#endif
    // Step 1-2 ctB0
#if debug
    printf("ctB0: START - Step 1-1\n");
#endif
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(lado))
    for (int k=0; k<lado; k++) {
        v_ctB0[k]=EvalMultVect(EvalRotateOpt(ct2, k*lado), vec_from_pred(nElem, [lado, k](int ell){return ell%lado == k;}));
#if debug
        printf("ctB0: %d/%d\n", k, lado);
#endif
    }
#if debug
    printf("ctB0: SumMany\n");
#endif
    Ciphertext<Element> ctB0 = cc->EvalAddMany(v_ctB0);
#if debug
    printf("ctB0: END - Step 1-1\n");
#endif
    // Step 2
#if debug
    printf("ctAB: START - Step 2\n");
#endif
    v_ctAB[0] = cc->EvalMult(ctA0, ctB0);
#if debug
    printf("ctAB: 0/%d\n", lado);
#endif
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(lado-1))
    for (int k=1; k<lado; k++) {
        v_ctAB[k] = cc->EvalMult(cc->EvalAdd(EvalMultVect(EvalRotateOpt(ctA0, k), vec_from_pred(nElem, [lado, k](int ell){return (unsigned)(ell%lado) < lado-k;})),
                                             EvalMultVect(EvalRotateOpt(ctA0, k-lado), vec_from_pred(nElem, [lado, k](int ell){return (unsigned)(ell%lado-lado+k) < k;}))),
                                 EvalRotateOpt(ctB0, lado*k));
#if debug
    printf("ctAB: %d/%d\n", k, lado);
#endif
    }
    return cc->EvalAddMany(v_ctAB);
#if debug
    printf("ctAB: END - Step 2\n");
#endif
}

template <class Element>
Ciphertext<Element> LessMultiplicationsMatMult(Ciphertext<Element> ct1,
                                               Ciphertext<Element> ct2,
                                               int lado, usint lvlStrassen=0) {
    #if debug
    printf("LessMultiplicationsMatMult(%s, %s, %d, %d)\n", ct1->GetKeyTag().c_str(), ct2->GetKeyTag().c_str(), lado, lvlStrassen);
    #endif
    if (lado < 1) {
        OPENFHE_THROW("El lado no es valido, debe ser mayor o igual a 1");
    } else if (lado == 1) {
        return ct1->GetCryptoContext()->EvalMult(ct1, ct2);
    } else {
        int ladoStr = lado/(1 << lvlStrassen);
        if (ladoStr < 1) {
            OPENFHE_THROW("El lado de Strassen no es valido, debe ser mayor o igual a 1");
        } else if (ladoStr == 1) {
            return EvalMultVect(ct1->GetCryptoContext()->EvalMult(ct1, ct2), vec_from_pred(ct1->GetSlots(), [](int i){return i==0;}));
        } else {
            auto cc = ct1->GetCryptoContext();
            int slotsMax = cc->GetRingDimension()/2,
                // nElem = lado*lado, nSlots = nElem*lado,
                nSlotsStr = std::max(pow(ladoStr, 3), pow(lado, 2));
            if (nSlotsStr > slotsMax)
                OPENFHE_THROW("El numero de slots necesarios para el calculo es mayor al numero de slots maximos");
            Ciphertext<Element> ctA = ct1->Clone(), ctB = ct2->Clone();
            if (nSlotsStr > ct1->GetSlots()) {
                ctA->SetSlots(nSlotsStr);
                ctB->SetSlots(nSlotsStr);
            }
            // Prepara A & B
            std::vector<Ciphertext<Element>> v_ctA = std::vector<Ciphertext<Element>>(ladoStr),
                                             v_ctB = std::vector<Ciphertext<Element>>(ladoStr);
            #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(ladoStr))
            for (int i=0; i<ladoStr; i++) {
                int rot_prep = -((i*ladoStr)%lado+floor(i*ladoStr/lado)*lado*ladoStr);
                v_ctA[i] = EvalRotateOpt(
                    EvalMultVect(ctA, vec_from_pred(nSlotsStr, [ladoStr, lado, i](int j){return j<ladoStr*lado && j%lado==i;})),
                    rot_prep+i);
                v_ctB[i] = EvalRotateOpt(
                    EvalMultVect(ctB, vec_from_pred(nSlotsStr, [ladoStr, lado, i](int j){return j<ladoStr*lado && floor(j/lado)==i && j%lado<ladoStr;})),
                    rot_prep+i*lado);
            }
            ctA = cc->EvalAddMany(v_ctA);
            v_ctA.clear();
            ctB = cc->EvalAddMany(v_ctB);
            v_ctB.clear();
            for (int i=0; i<log2(ladoStr); i++) {
                ctA += EvalRotateOpt(ctA, -(1 << i));
                ctB += EvalRotateOpt(ctB, -(1 << i)*lado);
            }
            // Multiplica A & B
            Ciphertext<Element> ctC = ctA * ctB;
            // Suma Los resultados
            if (nSlotsStr > ct1->GetSlots()) {
                ctC->SetSlots(ct1->GetSlots());
                ctC = cc->EvalMult(ctC, nSlotsStr/ct1->GetSlots());
            } else {
                int l = (int)floor(log2(lado/ladoStr));
                for (int i=0; i<log2(ladoStr); i++) {
                    ctC += EvalRotateOpt(ctC, pow(lado, i/l)*(i%l+1)*ladoStr);
                }
                ctC = EvalMultVect(ctC, vec_from_pred(nSlotsStr, [lado, ladoStr](int i){return i<ladoStr*lado && i%lado<ladoStr && floor(i/lado)<ladoStr;}));
            }
            return ctC;
        }
    }
}

template <class Element>
Ciphertext<Element> StrassenMatMult(Ciphertext<Element> ct1,
                                    Ciphertext<Element> ct2,
                                    int lado, usint strassenAtSize=1,
                                    MatrixMultiplicationTechnique mmTech=MatrixMultiplicationTechnique::INVALID_MATRIX_MULTIPLICATION_TECHNIQUE,
                                    usint lvlStrassen=0) {
    #if debug
    printf("StrassenMatMult(%s, %s, %d, %d, %d, %d)\n", ct1->GetKeyTag().c_str(), ct2->GetKeyTag().c_str(), lado, strassenAtSize, mmTech, lvlStrassen);
    #endif
    if (strassenAtSize == 0)
        OPENFHE_THROW("strassenAtSize must be greater than 0");
    int ladoStrassen = lado/(1 << lvlStrassen);
    if (ladoStrassen <= strassenAtSize) {
        if (ladoStrassen == 1) {
            #if debug
            printf("lvl%d -> Base case\n", lvlStrassen);
            #endif
            return EvalMultVect(ct1->GetCryptoContext()->EvalMult(ct1, ct2), vec_from_pred(ct1->GetSlots(), [](int i){return i==0;}));
        }
        switch (mmTech) {
            case MatrixMultiplicationTechnique::HE_MATRIX_MULTIPLICATION:
                return HEMatMult(ct1->Clone(), ct2->Clone(), lado, lvlStrassen);
                break;
            case MatrixMultiplicationTechnique::LESS_MULTIPLICATIONS_MATRIX_MULTIPLICATION:
                return LessMultiplicationsMatMult(ct1->Clone(), ct2->Clone(), lado, lvlStrassen);
                break;
            default:
                OPENFHE_THROW("Invalid MatrixMultiplicationTechnique");
        }
    } else {
        auto cc = ct1->GetCryptoContext();
        std::vector<Ciphertext<Element>> ct1_rot = std::vector<Ciphertext<Element>>(3),
                                         ct2_rot = std::vector<Ciphertext<Element>>(3),
                                         ct_prep_m = std::vector<Ciphertext<Element>>(10),
                                         ct_m = std::vector<Ciphertext<Element>>(7),
                                         ct_c = std::vector<Ciphertext<Element>>(4);
        // Cuadrantes
        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(3))
        for (int i=0; i<3; i++) {
            int rot = RotationQuadrantStrassen(i+1, 0, lado, lvlStrassen);
            #if debug
            printf("lvl%d -> Rot(%d->0): %d\n", lvlStrassen, i+1, rot);
            #endif
            ct1_rot[i] = EvalRotateOpt(ct1, rot);
            ct2_rot[i] = EvalRotateOpt(ct2, rot);
        }
        // Prepara M1-M7
        std::vector<std::function<Ciphertext<Element>()>> operaciones = {
            [cc, ct1, ct1_rot](){return cc->EvalAdd(ct1, ct1_rot[2]);},   // PM0
            [cc, ct2, ct2_rot](){return cc->EvalAdd(ct2, ct2_rot[2]);},   // PM1
            [cc, ct1_rot](){return cc->EvalAdd(ct1_rot[1], ct1_rot[2]);}, // PM2
            [cc, ct2_rot](){return cc->EvalSub(ct2_rot[0], ct2_rot[2]);}, // PM3
            [cc, ct2, ct2_rot](){return cc->EvalSub(ct2_rot[1], ct2);},   // PM4
            [cc, ct1, ct1_rot](){return cc->EvalAdd(ct1, ct1_rot[0]);},   // PM5
            [cc, ct1, ct1_rot](){return cc->EvalSub(ct1_rot[1], ct1);},   // PM6
            [cc, ct2, ct2_rot](){return cc->EvalAdd(ct2, ct2_rot[0]);},   // PM7
            [cc, ct1_rot](){return cc->EvalSub(ct1_rot[0], ct1_rot[2]);}, // PM8
            [cc, ct2_rot](){return cc->EvalAdd(ct2_rot[1], ct2_rot[2]);}  // PM9
        };
        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(10))
        for (int i=0; i<10; i++) {
            ct_prep_m[i] = operaciones[i]();
            #if debug
            printf("lvl%d -> PM%d\n", lvlStrassen, i);
            #endif
        }
        // M1-M7
        operaciones = {
            [lado, strassenAtSize, mmTech, lvlStrassen, ct_prep_m](){return StrassenMatMult(ct_prep_m[0], ct_prep_m[1], lado, strassenAtSize, mmTech, lvlStrassen+1);},        // M0
            [lado, strassenAtSize, mmTech, lvlStrassen, ct_prep_m, ct2](){return StrassenMatMult(ct_prep_m[2], ct2, lado, strassenAtSize, mmTech, lvlStrassen+1);},            // M1
            [lado, strassenAtSize, mmTech, lvlStrassen, ct_prep_m, ct1](){return StrassenMatMult(ct1, ct_prep_m[3], lado, strassenAtSize, mmTech, lvlStrassen+1);},            // M2
            [lado, strassenAtSize, mmTech, lvlStrassen, ct_prep_m, ct1_rot](){return StrassenMatMult(ct1_rot[2], ct_prep_m[4], lado, strassenAtSize, mmTech, lvlStrassen+1);}, // M3
            [lado, strassenAtSize, mmTech, lvlStrassen, ct_prep_m, ct2_rot](){return StrassenMatMult(ct_prep_m[5], ct2_rot[2], lado, strassenAtSize, mmTech, lvlStrassen+1);}, // M4
            [lado, strassenAtSize, mmTech, lvlStrassen, ct_prep_m](){return StrassenMatMult(ct_prep_m[6], ct_prep_m[7], lado, strassenAtSize, mmTech, lvlStrassen+1);},        // M5
            [lado, strassenAtSize, mmTech, lvlStrassen, ct_prep_m](){return StrassenMatMult(ct_prep_m[8], ct_prep_m[9], lado, strassenAtSize, mmTech, lvlStrassen+1);}         // M6
        };
        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(7)) schedule(auto)
        for (int i=0; i<7; i++) {
            ct_m[i] = operaciones[i]();
            #if debug
            printf("lvl%d -> P%d\n", lvlStrassen, i);
            #endif
        }
        ct1_rot.clear();
        ct2_rot.clear();
        ct_prep_m.clear();
        // C1-C4
        operaciones = {
            [cc, ct_m](){return cc->EvalSub(cc->EvalAddMany({ct_m[0], ct_m[3], ct_m[6]}), ct_m[4]);},                                                                                      // C1
            [cc, ct_m, lado, lvlStrassen](){return EvalRotateOpt(cc->EvalAdd(ct_m[2], ct_m[4]), RotationQuadrantStrassen(0, 1, lado, lvlStrassen));},                                      // C2
            [cc, ct_m, lado, lvlStrassen](){return EvalRotateOpt(cc->EvalAdd(ct_m[1], ct_m[3]), RotationQuadrantStrassen(0, 2, lado, lvlStrassen));},                                      // C3
            [cc, ct_m, lado, lvlStrassen](){return EvalRotateOpt(cc->EvalSub(cc->EvalAddMany({ct_m[0], ct_m[2], ct_m[5]}), ct_m[1]), RotationQuadrantStrassen(0, 3, lado, lvlStrassen));}, // C4
        };
        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(4))
        for (int i=0; i<4; i++) {
            ct_c[i] = operaciones[i]();
            #if debug
            printf("lvl%d -> C%d\n", lvlStrassen, i);
            #endif
        }
        ct_m.clear();
        Ciphertext<Element> ct = cc->EvalAddMany(ct_c);
        ct_c.clear();
        if (lvlStrassen != 0)
            ct = EvalMultVect(ct, vec_from_pred(ct1->GetSlots(), [lado, ladoStrassen](int i){return i%lado<ladoStrassen && i/lado<ladoStrassen;}));
        return ct;
    }
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalMatrixMult(ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2,
                                                             MatrixMultiplicationTechnique mmTech,
                                                             usint strassenAtSize,
                                                             usint nRows1, usint nRows2) const {
    #if debug
    printf("EvalMatrixMult(%s, %s, %d, %d, %d, %d)\n", ct1->GetKeyTag().c_str(), ct2->GetKeyTag().c_str(), mmTech, strassenAtSize, nRows1, nRows2);
    #endif
    if (ct1->GetSlots() == 0 || ct2->GetSlots() == 0) {
        OPENFHE_THROW("the vectors of ciphertexts to be multiplied cannot be empty");
    }
    usint nCols1, nCols2;
    if (nRows1 == 0) {
        if (sqrt(ct1->GetSlots()) != floor(sqrt(ct1->GetSlots()))) {
            OPENFHE_THROW("the number of rows of the first matrix must be specified");
        }
        nRows1 = uint(sqrt(ct1->GetSlots()));
        nCols1 = nRows1;
    } else if (ct1->GetSlots()%nRows1 != 0) {
        OPENFHE_THROW("the number of columns of the first matrix must be a unsigned integer, this be calculated by the number of elements in the vector divided by the number of rows");
    } else {
        nCols1 = uint(ct1->GetSlots()/nRows1);
    }
    if (nRows2 == 0) {
        nRows2 = nCols1;
    }
    if (ct2->GetSlots()%nRows2 != 0) {
        OPENFHE_THROW("the number of columns of the second matrix must be a unsigned integer, this be calculated by the number of elements in the vector divided by the number of rows.");
    } else {
        nCols2 = uint(ct2->GetSlots()/nRows2);
    }
    if (strassenAtSize != 0 && !(nRows1 == nCols1 && nRows1 == nRows2 && nRows1 == nCols2) && log2(nRows1) != floor(log2(nRows1))) {
        OPENFHE_THROW("the matrices must be square and with sides power of 2 for Strassen's algorithm");
    }
    auto cc = ct1->GetCryptoContext();
    if (ct1->GetSlots() == 1 || ct2->GetSlots() == 1) {
        return cc->EvalMult(ct1, ct2);
    } else {
        if (nCols1 != nRows2) {
        OPENFHE_THROW("the number of columns of the first matrix must be equal to the number of rows of the second matrix");
        }
        if (nRows1*nCols2 > ct1->GetCryptoContext()->GetRingDimension()/2) {
            OPENFHE_THROW("the resulting matrix is too large to be encoded in this context");
        }

        // SOLO MATRICES CUADRADAS
        if (nRows1 != nCols1 || nRows2 != nCols2)
            OPENFHE_THROW("the matrices must be square (por ahora)");
        // SOLO MATRICES CON LADO POTENCIA DE 2
        if (1 << (int)(floor(log2(nRows1))) != nRows1)
            OPENFHE_THROW("Number of sides must be a power of 2");
        if (strassenAtSize==1) {
            return StrassenMatMult(ct1->Clone(), ct2->Clone(), nRows1);
        } else {
            if (mmTech == MatrixMultiplicationTechnique::LESS_MULTIPLICATIONS_MATRIX_MULTIPLICATION &&
                    strassenAtSize==0 && cc->GetRingDimension()/2 < pow(nRows1, 3))
                strassenAtSize = (1 << (int)(floor(log2(cbrt(cc->GetRingDimension()/2)))));
            if (strassenAtSize==0) {
                switch (mmTech) {
                    case MatrixMultiplicationTechnique::HE_MATRIX_MULTIPLICATION:
                        return HEMatMult(ct1->Clone(), ct2->Clone(), nRows1);
                        break;
                    case MatrixMultiplicationTechnique::LESS_MULTIPLICATIONS_MATRIX_MULTIPLICATION:
                        return LessMultiplicationsMatMult(ct1->Clone(), ct2->Clone(), nRows1);
                        break;
                    default:
                        OPENFHE_THROW("Invalid MatrixMultiplicationTechnique");
                }
            } else {
                if (!(nRows1 == nCols1 && nRows1 == nRows2 && nRows1 == nCols2) && log2(nRows1) != floor(log2(nRows1))) {
                    OPENFHE_THROW("the matrices must be square and with sides power of 2 for Strassen's algorithm");
                }
                return StrassenMatMult(ct1->Clone(), ct2->Clone(), nRows1, strassenAtSize, mmTech);
            }
        }
    }
}

}  // namespace lbcrypto

// the code below is from base-advancedshe-impl.cpp
namespace lbcrypto {

template class AdvancedSHEBase<DCRTPoly>;

}  // namespace lbcrypto
