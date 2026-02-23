<%--
  Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).

  WSO2 LLC. licenses this file to you under the Apache License,
  Version 2.0 (the "License"); you may not use this file except
  in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied. See the License for the
  specific language governing permissions and limitations
  under the License.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
    String sessionDataKey = request.getParameter("sessionDataKey");
    if (sessionDataKey == null) {
        sessionDataKey = "";
    }
    // The commonauth endpoint on IS that the form will submit to.
    // This should match the IS host where the authenticator is deployed.
    String commonAuthUrl = "https://localhost:9443/commonauth";
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Select Organization - WSO2 API Manager</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #f5f6f8;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            color: #333;
        }

        .container {
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 12px rgba(0, 0, 0, 0.1);
            padding: 40px;
            width: 100%;
            max-width: 420px;
        }

        .logo {
            text-align: center;
            margin-bottom: 24px;
        }

        .logo img {
            height: 40px;
        }

        .logo h2 {
            color: #ff7300;
            font-size: 18px;
            margin-top: 8px;
        }

        h1 {
            font-size: 22px;
            font-weight: 600;
            text-align: center;
            margin-bottom: 8px;
            color: #1a1a1a;
        }

        .subtitle {
            text-align: center;
            color: #666;
            font-size: 14px;
            margin-bottom: 28px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 6px;
            color: #444;
        }

        input[type="text"] {
            width: 100%;
            padding: 10px 14px;
            font-size: 14px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            outline: none;
            transition: border-color 0.2s;
        }

        input[type="text"]:focus {
            border-color: #ff7300;
            box-shadow: 0 0 0 3px rgba(255, 115, 0, 0.1);
        }

        input[type="text"]::placeholder {
            color: #9ca3af;
        }

        .btn-submit {
            width: 100%;
            padding: 12px;
            font-size: 15px;
            font-weight: 600;
            color: #fff;
            background-color: #ff7300;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .btn-submit:hover {
            background-color: #e66800;
        }

        .btn-submit:disabled {
            background-color: #ffc18a;
            cursor: not-allowed;
        }

        .error-message {
            color: #dc2626;
            font-size: 13px;
            margin-top: 4px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h2>WSO2 API Manager</h2>
        </div>

        <h1>Select Your Organization</h1>
        <p class="subtitle">Enter your organization's tenant domain to continue</p>

        <form id="tenantForm" action="<%= commonAuthUrl %>" method="GET">
            <input type="hidden" name="sessionDataKey" value="<%= sessionDataKey %>" />

            <div class="form-group">
                <label for="tenantDomain">Tenant Domain</label>
                <input type="text"
                       id="tenantDomain"
                       name="tenantDomain"
                       placeholder="e.g., abc.com"
                       required
                       autocomplete="off"
                       autofocus />
                <div class="error-message" id="errorMsg">Please enter a valid tenant domain.</div>
            </div>

            <button type="submit" class="btn-submit" id="submitBtn">Continue</button>
        </form>
    </div>

    <script>
        document.getElementById('tenantForm').addEventListener('submit', function(e) {
            var tenantDomain = document.getElementById('tenantDomain').value.trim();
            var errorMsg = document.getElementById('errorMsg');
            var submitBtn = document.getElementById('submitBtn');

            if (!tenantDomain) {
                e.preventDefault();
                errorMsg.style.display = 'block';
                return;
            }

            errorMsg.style.display = 'none';

            // Update the input value to trimmed version.
            document.getElementById('tenantDomain').value = tenantDomain;

            // Disable button to prevent double submit.
            submitBtn.disabled = true;
            submitBtn.textContent = 'Redirecting...';
        });

        document.getElementById('tenantDomain').addEventListener('input', function() {
            document.getElementById('errorMsg').style.display = 'none';
        });
    </script>
</body>
</html>
