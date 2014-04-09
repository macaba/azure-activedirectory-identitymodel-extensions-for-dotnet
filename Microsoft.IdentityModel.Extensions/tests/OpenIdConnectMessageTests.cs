//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using Microsoft.IdentityModel.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Reflection;
using System.Web;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class OpenIdConnectMessageTests
    {
        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup( TestContext testContext )
        {
            // Start local STS
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            // Stop local STS
        }

        [TestInitialize]
        public void Initialize()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "CFB7A712-9FA8-4A31-8446-2EA93CECC2AC")]
        [Description("Tests: Constructors")]
        public void OpenIdConnectMessage_Constructors()
        {
            OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage();
            Assert.AreEqual(openIdConnectMessage.IssuerAddress, string.Empty);
            openIdConnectMessage = new OpenIdConnectMessage("http://www.got.jwt.com");
            Assert.AreEqual(openIdConnectMessage.IssuerAddress, "http://www.got.jwt.com");
            ExceptionProcessor exceptionProcessor = ExceptionProcessor.ArgumentNullException("issuerAddress");
            try
            {
                openIdConnectMessage = new OpenIdConnectMessage((string)null);
                exceptionProcessor.ProcessNoException();
            }
            catch (Exception exception)
            {
                exceptionProcessor.ProcessException(exception);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "B644D6D6-26C0-4417-AF9C-F59CFC5E7903")]
        [Description("Tests: Defaults")]
        public void OpenIdConnectMessage_Defaults()
        {
            OpenIdConnectMessage openIdConnectRequest = new OpenIdConnectMessage();

            Assert.IsNull(openIdConnectRequest.Acr_Values);
            Assert.IsNull(openIdConnectRequest.Client_Assertion);
            Assert.IsNull(openIdConnectRequest.Client_Assertion_Type);
            Assert.IsNull(openIdConnectRequest.Claims_Locales);
            Assert.IsNull(openIdConnectRequest.Client_Id);
            Assert.IsNull(openIdConnectRequest.Client_Secret);
            Assert.IsNull(openIdConnectRequest.Code);
            Assert.IsNull(openIdConnectRequest.Display);
            Assert.IsNull(openIdConnectRequest.Id_Token_Hint);
            Assert.IsNull(openIdConnectRequest.Login_Hint);
            Assert.IsNull(openIdConnectRequest.Max_Age);
            Assert.IsNull(openIdConnectRequest.Nonce);
            Assert.IsNull(openIdConnectRequest.Prompt);
            Assert.IsNull(openIdConnectRequest.Redirect_Uri);
            Assert.IsNull(openIdConnectRequest.Response_Mode);
            Assert.IsNull(openIdConnectRequest.Response_Type);
            Assert.IsNull(openIdConnectRequest.Scope);
            Assert.IsNull(openIdConnectRequest.State);
            Assert.IsNull(openIdConnectRequest.Ui_Locales);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "E3499C32-5062-4F89-A209-3024613EB73B")]
        [Description("Tests: GetSets")]
        public void OpenIdConnectRequest_GetSets()
        {
            OpenIdConnectMessage openIdConnectRequest = new OpenIdConnectMessage();
            Type type = typeof(OpenIdConnectParameterNames);
            FieldInfo[] fields = type.GetFields(BindingFlags.DeclaredOnly | BindingFlags.Public | BindingFlags.Static);
            foreach (FieldInfo fieldInfo in fields)
            {
                TestUtilities.GetSet(openIdConnectRequest, fieldInfo.Name, null, new object[] { fieldInfo.Name, null, fieldInfo.Name + fieldInfo.Name });
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "38024A53-CF6A-48C4-8AF3-E9C97E2B86FC")]
        [Description( "Tests: Publics" )]
        public void OpenIdConnectRequest_Publics()
        {
            string issuerAddress = "http://gotJwt.onmicrosoft.com";
            string redirect_uri = "http://gotJwt.onmicrosoft.com/signedIn";
            string resource = "location data";
            string customParameterName = "Custom Parameter Name";
            string customParameterValue = "Custom Parameter Value";

            // Empty string
            OpenIdConnectMessage openIdConnectRequest = new OpenIdConnectMessage();
            string queryString = openIdConnectRequest.BuildRedirectUrl();
            string expectedQueryString = string.Empty;
            Assert.AreEqual(expectedQueryString, queryString);
            
            // IssuerAddress only
            openIdConnectRequest = new OpenIdConnectMessage(issuerAddress);
            queryString = openIdConnectRequest.BuildRedirectUrl();
            expectedQueryString = issuerAddress;
            Assert.AreEqual(expectedQueryString, queryString);

            // IssuerAdderss and Redirect_uri
            openIdConnectRequest = new OpenIdConnectMessage(issuerAddress);
            openIdConnectRequest.Redirect_Uri = redirect_uri;
            queryString = openIdConnectRequest.BuildRedirectUrl();
            expectedQueryString = 
                issuerAddress +
                "?" +
                HttpUtility.UrlEncode(OpenIdConnectParameterNames.Redirect_Uri) + 
                "=" +
                HttpUtility.UrlEncode(redirect_uri);
            Assert.AreEqual(expectedQueryString, queryString);

            // IssuerAdderss empty just Redirect_uri
            openIdConnectRequest = new OpenIdConnectMessage();
            openIdConnectRequest.Redirect_Uri = redirect_uri;
            queryString = openIdConnectRequest.BuildRedirectUrl();
            expectedQueryString =
                "?" +
                HttpUtility.UrlEncode(OpenIdConnectParameterNames.Redirect_Uri) +
                "=" +
                HttpUtility.UrlEncode(redirect_uri);
            Assert.AreEqual(expectedQueryString, queryString);

            // IssuerAdderss, Redirect_uri, Response
            openIdConnectRequest = new OpenIdConnectMessage(issuerAddress);
            openIdConnectRequest.Redirect_Uri = redirect_uri;
            openIdConnectRequest.Resource = resource;
            queryString = openIdConnectRequest.BuildRedirectUrl();
            expectedQueryString =
                issuerAddress +
                "?" +
                HttpUtility.UrlEncode(OpenIdConnectParameterNames.Redirect_Uri) +
                "=" +
                HttpUtility.UrlEncode(redirect_uri) +
                "&" +
                HttpUtility.UrlEncode(OpenIdConnectParameterNames.Resource) +
                "=" +
                HttpUtility.UrlEncode(resource);

            Assert.AreEqual(expectedQueryString, queryString);

            // IssuerAdderss, Redirect_uri, Response, customParam
            openIdConnectRequest = new OpenIdConnectMessage(issuerAddress);
            openIdConnectRequest.Parameters.Add(customParameterName, customParameterValue);
            openIdConnectRequest.Redirect_Uri = redirect_uri;
            openIdConnectRequest.Resource = resource;
            queryString = openIdConnectRequest.BuildRedirectUrl();
            expectedQueryString =
                issuerAddress +
                "?" +
                HttpUtility.UrlEncode(customParameterName) +
                "=" +
                HttpUtility.UrlEncode(customParameterValue) +
                "&" +
                HttpUtility.UrlEncode(OpenIdConnectParameterNames.Redirect_Uri) +
                "=" +
                HttpUtility.UrlEncode(redirect_uri) +
                "&" +
                HttpUtility.UrlEncode(OpenIdConnectParameterNames.Resource) +
                "=" +
                HttpUtility.UrlEncode(resource);

            Assert.AreEqual(expectedQueryString, queryString);
        }
    }
}

