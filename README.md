# AndroidKeystoreCrypto
AES encrypt decrypt with Android Keystore

## Using example Code


    private static String getKeyStoreSecureString(String pureString){
        try {
            SecureKey keyStoreLib = new SecureKey();
            byte[] encryptBytes = keyStoreLib.encryptText(pureString);
            // Can write this byte array to file
            return Base64.encodeToString(encryptBytes, Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String getPureString(String secureString) {
        try {
            SecureKey keyStoreLib = new SecureKey();
            byte[] encryptedBytes = Base64.decode(secureString, Base64.NO_WRAP);
            return keyStoreLib.decryptData(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
