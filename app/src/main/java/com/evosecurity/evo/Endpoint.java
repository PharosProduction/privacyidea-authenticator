/*
  privacyIDEA Authenticator

  Authors: Nils Behlen <nils.behlen@netknights.it>

  Copyright (c) 2017-2019 NetKnights GmbH

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

package com.evosecurity.evo;

import android.util.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import static com.evosecurity.evo.AppConstants.CONNECT_TIMEOUT;
import static com.evosecurity.evo.AppConstants.READ_TIMEOUT;
import static com.evosecurity.evo.AppConstants.STATUS_ENDPOINT_ERROR;
import static com.evosecurity.evo.AppConstants.STATUS_ENDPOINT_MALFORMED_URL;
import static com.evosecurity.evo.AppConstants.STATUS_ENDPOINT_UNKNOWN_HOST;
import static com.evosecurity.evo.Util.logprint;

class Endpoint {

    private boolean sslVerify;
    private String url;
    private Map<String, String> data;
    private Interfaces.EndpointCallback callback;

    Endpoint(boolean sslVerify, String url, Map<String, String> data, Interfaces.EndpointCallback callback) {
        this.sslVerify = sslVerify;
        this.url = url;
        this.data = data;
        this.callback = callback;
    }

    private URL buildURL() {
        try {
//            return new URL(this.url);
            return new URL("https://demo3.evosecurity.com/ttype/push");
        } catch (MalformedURLException e) {
            callback.updateStatus(STATUS_ENDPOINT_MALFORMED_URL);
            e.printStackTrace();

            return null;
        }
    }

    private HttpURLConnection openConnection(URL url) {
        try {
            HttpURLConnection con;

            if (url.getProtocol().equals("https")) {
                con = (HttpsURLConnection) url.openConnection();

                if (!sslVerify) {
                    con = turnOffSSLVerification((HttpsURLConnection) con);
                }
            } else {
                con = (HttpURLConnection) url.openConnection();
            }

            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("POST");
            con.setReadTimeout(READ_TIMEOUT);
            con.setConnectTimeout(CONNECT_TIMEOUT);

            return con;
        } catch (IOException e) {
            callback.updateStatus(STATUS_ENDPOINT_MALFORMED_URL);
            e.printStackTrace();

            return null;
        }
    }

    boolean connect() {
        URL url = buildURL();
        if (url == null) return false;

        HttpURLConnection con = openConnection(url);
        if (con == null) return false;

        OutputStream os;
        try {
            os = con.getOutputStream();
        } catch (IOException e) {
            e.printStackTrace();
            callback.updateStatus(STATUS_ENDPOINT_UNKNOWN_HOST);
            return false;
        }

        OutputStreamWriter streamWriter = new OutputStreamWriter(os, StandardCharsets.UTF_8);
        BufferedWriter writer = new BufferedWriter(streamWriter);

        try {
            String toSend = "";

            for (String key : data.keySet()) {
                if (key.equals("serial")) {
                    String[] vals = data.get(key).split("-");
                    String serial = vals[vals.length - 1];
                    toSend += key + "=" + serial;
                } else {
                    toSend += key + "=" + data.get(key);
                }

                logprint(toSend);
                writer.write(toSend);
                toSend = "&";
            }

            writer.flush();
            writer.close();
            os.close();
            con.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            int responsecode = con.getResponseCode();
            BufferedReader br;
            String line;
            StringBuilder response = new StringBuilder();
            try {
                br = new BufferedReader(new InputStreamReader(con.getInputStream()));
                while ((line = br.readLine()) != null) {
                    response.append(line);
                }
                callback.responseReceived(response.toString(), responsecode);

                con.disconnect();

                return true;
            } catch (IOException e) {
                callback.updateStatus(STATUS_ENDPOINT_ERROR);
                e.printStackTrace();
            }
        } catch (IOException e) {
            callback.updateStatus(STATUS_ENDPOINT_ERROR);
            e.printStackTrace();
        }

        con.disconnect();

        return false;
    }

    private HttpsURLConnection turnOffSSLVerification(HttpsURLConnection con) {
        logprint("Turning SSL verification off...");
        final TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[]{};
                    }
                }
        };
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        con.setSSLSocketFactory(sslSocketFactory);
        con.setHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
        logprint("Done.");
        return con;
    }
}
