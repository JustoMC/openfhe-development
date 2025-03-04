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
#include "schemebase/base-matrixshe.h"

#include "key/privatekey.h"
#include "cryptocontext.h"
#include "schemebase/base-scheme.h"

namespace lbcrypto {

template <class Element>
Ciphertext<Element> MatrixSHEBase<Element>::EvalMatrixMult(ConstCiphertext<Element> ciphertext1,
                                                             ConstCiphertext<Element> ciphertext2,
                                                             usint numRows1,
                                                             usint numRows2
                                                            ) const {
    if (ciphertext1->GetSlots() == 0 || ciphertext2->GetSlots() == 0) {
        OPENFHE_THROW("the vectors of ciphertexts to be multiplied cannot be empty");
    }
    usint numCols1, numCols2;
    if (numRows1 == 0) {
        if (sqrt(ciphertext1->GetSlots()) != floor(sqrt(ciphertext1->GetSlots()))) {
            OPENFHE_THROW("the number of rows of the first matrix must be specified");
        }
        numRows1 = uint(sqrt(ciphertext1->GetSlots()));
        numCols1 = numRows1;
    } else if (ciphertext1->GetSlots()%numRows1 != 0) {
        OPENFHE_THROW("the number of columns of the first matrix must be a unsigned integer, this be calculated by the number of elements in the vector divided by the number of rows");
    } else {
        numCols1 = uint(ciphertext1->GetSlots()/numRows1);
    }
    if (numRows2 == 0) {
        numRows2 = numCols1;
    }
    if (ciphertext2->GetSlots()%numRows2 != 0) {
        OPENFHE_THROW("the number of columns of the second matrix must be a unsigned integer, this be calculated by the number of elements in the vector divided by the number of rows.");
    } else {
        numCols2 = uint(ciphertext2->GetSlots()/numRows2);
    }
    if (numCols1 != numRows2) {
        OPENFHE_THROW("the number of columns of the first matrix must be equal to the number of rows of the second matrix");
    }
    if (numRows1*numCols2 > ciphertext1->GetCryptoContext()->GetRingDimension()/2) {
        OPENFHE_THROW("the resulting matrix is too large to be encoded in this context");
    }

    // SOLO MATRICES CUADRADAS
    if (numRows1 != numCols1 || numRows2 != numCols2)
        OPENFHE_THROW("the matrices must be square (por ahora)");
    // SOLO MATRICES CON LADO POTENCIA DE 2
    if (pow(2, floor(log2(numRows1))) != numRows1)
        OPENFHE_THROW("Number of sides must be a power of 2");
    
    auto cc = ciphertext1->GetCryptoContext();
    if (ciphertext1->GetSlots() == 1 && ciphertext2->GetSlots() == 1) {
        return cc->EvalMult(ciphertext1, ciphertext2);
    } else {
        #if true
        uint d = numRows1, n = numRows1*numRows1;
        std::vector<double> vk, uk=vec_from_pred(n, [d](uint i){return (i >= d-1) && (i < d);});
        // Step 1-1 ctA0
        Ciphertext<Element> ctA0 = cc->EvalMult(EvalRotate(ciphertext1, 1-d), cc->MakeCKKSPackedPlaintext(uk));
        for (int k = -d+2; k < d; k++) {
            if (k >= 0) {
                uk = vec_from_pred(n, [d, k](uint i){return 0 <= i-d*k < (d-k);});
            } else {
                uk = vec_from_pred(n, [d, k](uint i){return -k <= i-(d+k)*d && i < d;});
            }
            ctA0 = cc->EvalAdd(ctA0, cc->EvalMult(EvalRotate(ciphertext1, k), cc->MakeCKKSPackedPlaintext(uk)));
        return ctA0;
        }
        #else
        OPENFHE_THROW("Under construction");
        #endif

        return nullptr;
    }
}

Ciphertext EvalRotate(Ciphertext ciphertext, int32_t k) {
    k = k % ciphertext->GetSlots();
    if (k == 0) {
        return ciphertext;
    } else {
        auto cc = ciphertext->GetCryptoContext();
        return cc->EvalRotate(ciphertext, k);
    }
}
std::vector<double> vec_from_pred(uint n, std::function<bool(uint)> pred) {
    std::vector<double> vec;
    for (uint i = 0; i < n; i++) {
        vec.push_back(pred(i) ? 1 : 0);
    }
    return vec;
}

}  // namespace lbcrypto

// the code below is from base-matrixshe-impl.cpp
namespace lbcrypto {

template class MatrixSHEBase<DCRTPoly>;

}  // namespace lbcrypto
