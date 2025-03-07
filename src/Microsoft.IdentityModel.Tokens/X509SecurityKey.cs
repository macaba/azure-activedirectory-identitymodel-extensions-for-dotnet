//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// An <see cref="AsymmetricSecurityKey"/> that is backed by a <see cref="X509Certificate2"/>
    /// </summary>
    public class X509SecurityKey : AsymmetricSecurityKey
    {
        AsymmetricAlgorithm _privateKey;
        bool _privateKeyAvailabilityDetermined;
        AsymmetricAlgorithm _publicKey;
        object _thisLock = new Object();

        internal X509SecurityKey(JsonWebKey webKey)
            : base(webKey)
        {
            Certificate = new X509Certificate2(Convert.FromBase64String(webKey.X5c[0]));
            X5t = Base64UrlEncoder.Encode(Certificate.GetCertHash());
            webKey.ConvertedSecurityKey = this;
        }

        /// <summary>
        /// Instantiates a <see cref="X509SecurityKey"/> using a <see cref="X509Certificate2"/>
        /// </summary>
        /// <param name="certificate">The <see cref="X509Certificate2"/> to use.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="certificate"/> is null.</exception>
        public X509SecurityKey(X509Certificate2 certificate)
        {
            Certificate = certificate ?? throw LogHelper.LogArgumentNullException(nameof(certificate));
            KeyId = certificate.Thumbprint;
            X5t = Base64UrlEncoder.Encode(certificate.GetCertHash());
        }

        /// <summary>
        /// Instantiates a <see cref="X509SecurityKey"/> using a <see cref="X509Certificate2"/>.
        /// </summary>
        /// <param name="certificate">The <see cref="X509Certificate2"/> to use.</param>
        /// <param name="keyId">The value to set for the KeyId</param>
        /// <exception cref="ArgumentNullException">if <paramref name="certificate"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="keyId"/> is null or empty.</exception>
        public X509SecurityKey(X509Certificate2 certificate, string keyId)
        {
            Certificate = certificate ?? throw LogHelper.LogArgumentNullException(nameof(certificate));
            KeyId = string.IsNullOrEmpty(keyId) ? throw LogHelper.LogArgumentNullException(nameof(keyId)) : keyId;
            X5t = Base64UrlEncoder.Encode(certificate.GetCertHash());
        }

        /// <summary>
        /// Gets the key size.
        /// </summary>
        public override int KeySize
        {
            get => PublicKey.KeySize;
        }

        /// <summary>
        /// Gets the X5t of this <see cref="X509SecurityKey"/>.
        /// </summary>
        public string X5t { get; }

        /// <summary>
        /// Returns the private key from the <see cref="X509SecurityKey"/>.
        /// </summary>
        public AsymmetricAlgorithm PrivateKey
        {
            get
            {
                if (!_privateKeyAvailabilityDetermined)
                {
                    lock (ThisLock)
                    {
                        if (!_privateKeyAvailabilityDetermined)
                        {
#if NET461 || NETSTANDARD1_4 || NETSTANDARD2_0
                            _privateKey = RSACertificateExtensions.GetRSAPrivateKey(Certificate);
#else
                            _privateKey = Certificate.PrivateKey;
#endif
                            _privateKeyAvailabilityDetermined = true;
                        }
                    }
                }

                return _privateKey;
            }
        }

        /// <summary>
        /// Gets the public key from the <see cref="X509SecurityKey"/>.
        /// </summary>
        public AsymmetricAlgorithm PublicKey
        {
            get
            {
                if (_publicKey == null)
                {
                    lock (ThisLock)
                    {
                        if (_publicKey == null)
                        {
#if NET461 || NETSTANDARD1_4 || NETSTANDARD2_0
                            _publicKey = RSACertificateExtensions.GetRSAPublicKey(Certificate);
#else
                            _publicKey = Certificate.PublicKey.Key;
#endif
                        }
                    }
                }

                return _publicKey;
            }
        }

        object ThisLock
        {
            get { return _thisLock; }
        }

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        [System.Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
        public override bool HasPrivateKey
        {
            get { return (PrivateKey != null); }
        }

        /// <summary>
        /// Gets an enum indicating if a private key exists.
        /// </summary>
        /// <return>'Exists' if private key exists for sure; 'DoesNotExist' if private key doesn't exist for sure; 'Unknown' if we cannot determine.</return>
        public override PrivateKeyStatus PrivateKeyStatus
        {
            get
            {
                return PrivateKey == null ? PrivateKeyStatus.DoesNotExist : PrivateKeyStatus.Exists;
            }
        }

        /// <summary>
        /// Gets the <see cref="X509Certificate2"/>.
        /// </summary>
        public X509Certificate2 Certificate
        {
            get; private set;
        }

        /// <summary>
        /// Returns a bool indicating if this key is equivalent to another key.
        /// </summary>
        /// <return>true if the keys are equal; otherwise, false.</return>
        public override bool Equals(object obj)
        {
            if (!(obj is X509SecurityKey other))
                return false;

            return other.Certificate.Thumbprint.ToString() == Certificate.Thumbprint.ToString();
        }

        /// <summary>
        /// Returns an int hash code.
        /// </summary>
        /// <return>An int hash code</return>
        public override int GetHashCode()
        {
            return Certificate.GetHashCode();
        }
    }
}
