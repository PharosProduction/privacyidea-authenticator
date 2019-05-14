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

import android.app.Service;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.IBinder;
import android.widget.Toast;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationManagerCompat;

import static com.evosecurity.evo.AppConstants.NONCE;
import static com.evosecurity.evo.AppConstants.NOTIFICATION_ID;
import static com.evosecurity.evo.AppConstants.QUESTION;
import static com.evosecurity.evo.AppConstants.SERIAL;
import static com.evosecurity.evo.AppConstants.SIGNATURE;
import static com.evosecurity.evo.AppConstants.SSL_VERIFY;
import static com.evosecurity.evo.AppConstants.TITLE;
import static com.evosecurity.evo.AppConstants.URL;
import static com.evosecurity.evo.Util.logprint;

public class PushAuthService extends Service implements Interfaces.PushAuthCallbackInterface {
    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        super.onStartCommand(intent, flags, startId);
        logprint("AuthService started");
        if (intent == null) {
            logprint("intent is null, returning");
            return Service.START_STICKY;
        }
        logprint(intent.getExtras().toString());

        int notificationID = intent.getIntExtra(NOTIFICATION_ID, 654321);
        NotificationManagerCompat.from(this).cancel(notificationID);

        String serial = intent.getStringExtra(SERIAL);
        String nonce = intent.getStringExtra(NONCE);
        String title = intent.getStringExtra(TITLE);
        String url = intent.getStringExtra(URL);
        String signature = intent.getStringExtra(SIGNATURE);
        String question = intent.getStringExtra(QUESTION);
        boolean sslVerify = intent.getBooleanExtra(SSL_VERIFY, true);


        PrivateKey appPrivateKey = null;
        PublicKey publicKey = null;
        try {
            SecretKeyWrapper skw = new SecretKeyWrapper(getApplicationContext());
            appPrivateKey = skw.getPrivateKeyFor(serial);
            Util util = new Util(skw, getApplicationContext().getFilesDir().getAbsolutePath());
            publicKey = util.getPIPubkey(serial);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        if(appPrivateKey == null) {
            logprint("PushAuthService: appPrivateKey is null, Authentication is not started.");
            return Service.START_NOT_STICKY;    // Restart the Service in case of being killed, but don't redeliver the intent
        }
        if(publicKey == null) {
            logprint("PushAuthService: appPrivateKey is null, Authentication is not started.");
            return Service.START_NOT_STICKY;    // Restart the Service in case of being killed, but don't redeliver the intent
        }

            // start the authentication
            AsyncTask<Void, Integer, Boolean> pushAuth = new PushAuthTask(
                    new PushAuthRequest(nonce, url, serial, question, title, signature, sslVerify),
                    publicKey, appPrivateKey, this);
        pushAuth.execute();
        //return Service.START_REDELIVER_INTENT;
        return Service.START_NOT_STICKY;
    }

    @Override
    public void authenticationFinished(boolean success) {
        if (success) {
            Toast.makeText(getApplicationContext(), R.string.AuthenticationSuccessful, Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(getApplicationContext(), R.string.AuthenticationFailed, Toast.LENGTH_SHORT).show();
        }
    }
}
