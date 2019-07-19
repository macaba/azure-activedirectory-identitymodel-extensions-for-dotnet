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
using System.Collections.Generic;
using System.IO;
using RuntimeTestCommon;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;

namespace AdHocTests
{
    public class EpochTimeTests
    {
        public static void Run(string[] args)
        {
            IdentityModelEventSource.ShowPII = true;
            var testRuns = TestConfig.SetupTestRuns(
                new List<TestExecutor>
                {
                    EpochTimeTestExecutors.EpochTime_UtcNow,
                    EpochTimeTestExecutors.EpochTime_PassDate,
                    EpochTimeTestExecutors.EpochTime_UtcNow,
                    EpochTimeTestExecutors.EpochTime_PassDate,
                    EpochTimeTestExecutors.EpochTime_UtcNow,
                    EpochTimeTestExecutors.EpochTime_PassDate
                });

            var testConfig = TestConfig.ParseArgs(args);
            var testData = new TestData
            {
                NumIterations = testConfig.NumIterations,
            };

            // run each test to set any static data
            foreach (var testRun in testRuns)
                testRun.TestExecutor(testData);

            var assemblyVersion = typeof(EpochTime).Assembly.GetName().Version.ToString();
#if DEBUG
            var prefix = "DEBUG";
#else
            var prefix = "RELEASE";
#endif
            testConfig.Version = $"{prefix}-{assemblyVersion}";
            var logName = $"EpochTime-{testConfig.Version}_{DateTime.Now.ToString("yyyy.MM.dd.hh.mm.ss")}.txt";
            var directory = testConfig.LogDirectory;
            var logFile = Path.Combine(directory, logName);
            Directory.CreateDirectory(directory);

            TestRunner.Run(testConfig, testRuns, testData);
            File.WriteAllText(logFile, testConfig.Logger.Logs);
        }
    }
}
