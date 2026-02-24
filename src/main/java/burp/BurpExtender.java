/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.URL;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author n00b
 */
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IProxyListener {
    
    public String ExtensionName =  "AES Killer";
    public String TabName =  "AES Killer";
    public String _Header = "AES: Killer";
    AES_Killer _aes_killer;
    
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public Boolean isDebug = true;
    public Boolean isRunning = false;
    
    public Cipher cipher;
    public SecretKeySpec sec_key;
    public IvParameterSpec iv_param;
   
    public String _host;
    // Encryption
    public String _enc_type;
    public String _secret_key;
    public String _iv_param;
    // Decryption
    public String _dec_type;
    public String _secret_key_dec;
    public String _iv_param_dec;
    
    public String[] _req_param;
    public String[] _res_param;
    
    public String[] _obffusicatedChar;
    public String[] _replaceWithChar;
    
    public Boolean _exclude_iv = false;
    public Boolean _exclude_dec_keys = false;
    public Boolean _ignore_response = false;
    public Boolean _do_off = false;
    public Boolean _url_enc_dec = false;
    public Boolean _ciphertext_is_hex = false;
    public Boolean _is_req_body = false;
    public Boolean _is_res_body = false;
    public Boolean _is_req_param = false;
    public Boolean _is_res_param = false;
    public Boolean _is_ovrr_req_body = false;
    public Boolean _is_ovrr_res_body = false;
    public Boolean _is_ovrr_req_body_form = false;
    public Boolean _is_ovrr_res_body_form = false;
    public Boolean _is_ovrr_req_body_json = false;
    public Boolean _is_ovrr_res_body_json = false;
    
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.callbacks.setExtensionName(this.ExtensionName);
        
        _aes_killer = new AES_Killer(this);
        this.callbacks.addSuiteTab(this);
        this.stdout.println("AES_Killer Installed !!!");
    }

    @Override
    public String getTabCaption() {
        return this.TabName;
    }

    @Override
    public Component getUiComponent() {
        return this._aes_killer;
    }
    
    public void start_aes_killer(){
        this.callbacks.registerHttpListener(this);
        this.callbacks.registerProxyListener(this);
        this.isRunning = true;
    }
    
    public void stop_aes_killer(){
        this.callbacks.removeHttpListener(this);
        this.callbacks.removeProxyListener(this);
        this.isRunning = false;
    }
    
    private void print_output(String _src, String str){
        if(! isDebug){ return; }
        this.stdout.println(_src + " :: " + str);
    }
    
    private void print_error(String _src, String str){
        if(! isDebug){ return; }
        this.stderr.println(_src + " :: " + str);
    }
    
    public String get_host(String _url){
        try{
            URL abc = new URL(_url);
            return abc.getHost().toString();
        }catch (Exception ex){
            print_error("get_endpoint", _url);
            return _url;
        }
    }

    public String remove_0bff(String _paramString) {
        if (_paramString != null) {
          for(int i =0; i< this._obffusicatedChar.length; i++){
              _paramString = _paramString.replace(this._replaceWithChar[i], this._obffusicatedChar[i]);
          }
          return _paramString;
        }
        return _paramString;
    }
    
    public String do_0bff(String _paramString) {
        if (_paramString != null) {
          for(int i =0; i< this._obffusicatedChar.length; i++){
              _paramString = _paramString.replace(this._obffusicatedChar[i], this._replaceWithChar[i]);
          }
          return _paramString;
        }
        return _paramString;
    }
    
    public byte[] hexStringToBytes(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                                 + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }
    public String bytesToHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    public String do_decrypt(String _enc_str, boolean isResponse){
        try{
        	print_error("Do Decrypt Called, isResponse:", String.valueOf(isResponse));
        	String secretKey = this._secret_key;
        	String ivParam = this._iv_param;
        	if (this._exclude_dec_keys==false && isResponse) {
            	print_error("Setting KEy :", this._secret_key_dec.toString());
        		secretKey = this._secret_key_dec;
        		ivParam = this._iv_param_dec;
        	}
        	
        	print_error("GOT DECRYPTION KEY: ", secretKey.toString());
        	print_error("GOT DECRYPTION IV: ", ivParam.toString());
            cipher = Cipher.getInstance(this._enc_type);
            print_error("Cipher Type",this._enc_type);
            String enc_mode = "AES";
            if(this._enc_type.contains("DES/")) {
            	enc_mode = "DES";
            }
            print_error("IM HERE YO - 1",this._enc_type.toString());
            sec_key = new SecretKeySpec(this.helpers.base64Decode(secretKey),enc_mode);

            print_error("IM HERE YO - 2",this._enc_type.toString());
            if (this._exclude_iv){
                cipher.init(Cipher.DECRYPT_MODE, sec_key);
            }
            else {
                print_error("IM HERE YO - 3",this._enc_type.toString());
                iv_param = new IvParameterSpec(this.helpers.base64Decode(ivParam));
                cipher.init(Cipher.DECRYPT_MODE, sec_key, iv_param);
            }
            print_error("IM HERE YO - 4",this._enc_type.toString());
            if (this._url_enc_dec) { _enc_str = this.helpers.urlDecode(_enc_str); }
            if (this._do_off) { _enc_str = this.remove_0bff(_enc_str); }

            print_error("_ciphertext_is_hex is set",this._ciphertext_is_hex.toString());
            print_error("stringtobytes",hexStringToBytes(_enc_str).toString());
            if (this._ciphertext_is_hex) {
                _enc_str = new String(cipher.doFinal(hexStringToBytes(_enc_str)));
            } else {
                _enc_str = new String(cipher.doFinal(this.helpers.base64Decode(_enc_str)));
            }
            return _enc_str;
        }catch(Exception ex){
            print_error("do_decrypt", ex.getMessage());
            return _enc_str;
        }
    }

    public String do_encrypt(String _dec_str, boolean isResponse){
        try{
        	print_error("Encrypting isResponse:", String.valueOf(isResponse));
        	String secretKey = this._secret_key;
        	String ivParam = this._iv_param;
        	if (this._exclude_dec_keys==false && isResponse) {
            	print_error("Switching Key To :", this._secret_key_dec.toString());
        		secretKey = this._secret_key_dec;
        		ivParam = this._iv_param_dec;
        	}

        	print_error("GOT Encryption KEY: ", secretKey.toString());
        	print_error("GOT Encryption IV: ", ivParam.toString());
            cipher = Cipher.getInstance(this._enc_type);
            String enc_mode = "AES";
            if(this._enc_type.contains("DES/")) {
            	enc_mode = "DES";
            }
            sec_key = new SecretKeySpec(this.helpers.base64Decode(secretKey),enc_mode);

            if (this._exclude_iv){
                cipher.init(Cipher.ENCRYPT_MODE, sec_key);
            }
            else {
                iv_param = new IvParameterSpec(this.helpers.base64Decode(ivParam));
                cipher.init(Cipher.ENCRYPT_MODE, sec_key, iv_param);
            }

            if (this._ciphertext_is_hex) {
                _dec_str = bytesToHexString(cipher.doFinal(_dec_str.getBytes()));
            } else {
                _dec_str = new String(this.helpers.base64Encode(cipher.doFinal(_dec_str.getBytes())));
            }
            if (this._do_off) { _dec_str = this.do_0bff(_dec_str); }
            if (this._url_enc_dec) { _dec_str = this.helpers.urlEncode(_dec_str); }
            return _dec_str;
        }catch(Exception ex){
            print_error("do_decrypt", ex.getMessage());
            return _dec_str;
        }
    }
    
    
    public byte[] update_req_params (byte[] _request, List<String> headers, String[] _params, Boolean _do_enc, Boolean isResponse){
    	print_error("Updaing Request Params: ", isResponse.toString());
        for(int i = 0 ; i < _params.length; i++){
            IParameter _p = this.helpers.getRequestParameter(_request, _params[i]);
            if (_p == null || _p.getName().toString().length() == 0){ continue; }
            
            String _str = "";
            if(_do_enc) {
                _str = this.do_encrypt(_p.getValue().toString().trim(), isResponse);
            }
            else {
                _str = this.do_decrypt(_p.getValue().toString().trim(), isResponse);
            }
            
            if(this._is_ovrr_req_body){
                if (!headers.contains(this._Header)) { headers.add(this._Header); }
                _request = this.helpers.buildHttpMessage(headers, _str.getBytes());
                return _request;
            }
            
            if(this._is_ovrr_res_body){
                if (!headers.contains(this._Header)) { headers.add(this._Header); }
                _request = this.helpers.buildHttpMessage(headers, _str.getBytes());
                return _request;
            }

            
            IParameter _newP = this.helpers.buildParameter(_params[i], _str, _p.getType());
            _request = this.helpers.removeParameter(_request, _p);
            _request = this.helpers.addParameter(_request, _newP);
            if (!headers.contains(this._Header)) { headers.add(this._Header); }
            IRequestInfo reqInfo2 = helpers.analyzeRequest(_request);
            String tmpreq = new String(_request);
            String messageBody = new String(tmpreq.substring(reqInfo2.getBodyOffset())).trim();
            _request = this.helpers.buildHttpMessage(headers, messageBody.getBytes());
        }
        return _request;
    }
    
    public byte[] update_req_params_json(byte[] _request, List<String> headers, String[] _params, Boolean _do_enc, Boolean isResponse){
        for(int i=0; i< _params.length; i++){
            IParameter _p = this.helpers.getRequestParameter(_request, _params[i]);
            if (_p == null || _p.getName().toString().length() == 0){ continue; }
            
            String _str = "";
            if(_do_enc) {
                _str = this.do_encrypt(_p.getValue().toString().trim(), isResponse);
            }
            else {
                _str = this.do_decrypt(_p.getValue().toString().trim(), isResponse);
            }
            
            
            if(this._is_ovrr_req_body){
                if (!headers.contains(this._Header)) { headers.add(this._Header); }
                _request = this.helpers.buildHttpMessage(headers, _str.getBytes());
                return _request;
            }
            
            if(this._is_ovrr_res_body){
                if (!headers.contains(this._Header)) { headers.add(this._Header); }
                _request = this.helpers.buildHttpMessage(headers, _str.getBytes());
                return _request;
            }
            
            
            IRequestInfo reqInfo = helpers.analyzeRequest(_request);
            String tmpreq = new String(_request);
            String messageBody = new String(tmpreq.substring(reqInfo.getBodyOffset())).trim();

            int _fi = messageBody.indexOf(_params[i]);
            if(_fi < 0) { continue; }

            _fi = _fi + _params[i].length() + 3;
            int _si = messageBody.indexOf("\"", _fi);
            print_output("update_req_params_json", _str);
            print_output("update_req_params_json", messageBody.substring(0, _fi));
            print_output("update_req_params_json", messageBody.substring(_si, messageBody.length()));
            if (!headers.contains(this._Header)) { headers.add(this._Header); }
            messageBody = messageBody.substring(0, _fi) + _str + messageBody.substring(_si, messageBody.length());
            _request = this.helpers.buildHttpMessage(headers, messageBody.getBytes());
            
        }
        return _request;
    }
    
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
    	print_error("processHttpMessage", "");
        if (messageIsRequest) {
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            String URL = new String(reqInfo.getUrl().toString());
            List headers = reqInfo.getHeaders();
            
            if(this._host.contains(get_host(URL))) {
                
                if(this._is_req_body) {
                    // decrypting request body
                    String tmpreq = new String(messageInfo.getRequest());
                    String messageBody = new String(tmpreq.substring(reqInfo.getBodyOffset())).trim();
                    String decValue = this.do_decrypt(messageBody, false);
                    headers.add(new String(this._Header));
                    byte[] updateMessage = helpers.buildHttpMessage(headers, decValue.getBytes());
                    messageInfo.setRequest(updateMessage);
                    print_output("PPM-req", "Final Decrypted Request\n" + new String(updateMessage));
                }
                else if(this._is_req_param){
                    
                    byte[] _request = messageInfo.getRequest();
                    
                    if(reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON){
                        _request = update_req_params_json(_request, headers, this._req_param ,false, false);
                    }
                    else{
                        _request = update_req_params(_request, headers, this._req_param, false, false);                        
                    }
                    print_output("PPM-req", "Final Decrypted Request\n" + new String(_request));
                    messageInfo.setRequest(_request);
                    
                }
                else {
                    return;
                }
                
            }
        }
        else {
            if(this._ignore_response) { return; }
            // PPM Response
            print_error("processHttpMessage", "");
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            IResponseInfo resInfo = helpers.analyzeResponse(messageInfo.getResponse());
            String URL = new String(reqInfo.getUrl().toString());
            List headers = resInfo.getHeaders();
            
            if(this._host.contains(this.get_host(URL))){
                
                if(!headers.contains(this._Header)){ return; }
                
                if(this._is_res_body){
                    // Complete Response Body encryption
                    String tmpreq = new String(messageInfo.getResponse());
                    String messageBody = new String(tmpreq.substring(resInfo.getBodyOffset())).trim();
                    messageBody = do_encrypt(messageBody, true);
                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setResponse(updateMessage);
                    print_output("PPM-res", "Final Encrypted Response\n" + new String(updateMessage));
                }
                else if(this._is_ovrr_res_body){
                    String tmpreq = new String(messageInfo.getResponse());
                    String messageBody = new String(tmpreq.substring(resInfo.getBodyOffset())).trim();
                    messageBody = do_encrypt(messageBody, true);
                    
                    if(this._is_ovrr_res_body_form){
                        messageBody = this._req_param[0] + "=" + messageBody;
                    }
                    else if(this._is_ovrr_res_body_json){
                        messageBody = "{\"" + this._req_param[0] + "\":\"" + messageBody + "\"}";
                    }
                    
                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setResponse(updateMessage);
                    print_output("PPM-res", "Final Encrypted Response\n" + new String(updateMessage));
                }
                else if(this._is_res_param){
                    // implement left --------------------------
                    byte[] _response = messageInfo.getResponse();
                    
                    _response = this.update_req_params_json(_response, headers, this._res_param, true, true);
                    messageInfo.setResponse(_response);
                    print_output("PHTM-res", "Final Decrypted Response\n" + new String(_response));
                    
                }
                else{
                    return;
                }
            
            }
        }
    }

    
    
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    	print_error("processHttpMessage", "");

        if (messageIsRequest) {
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            String URL = new String(reqInfo.getUrl().toString());
            List headers = reqInfo.getHeaders();
            
            if(!headers.contains(this._Header)){ return; }
            
            if(this._host.contains(get_host(URL))){
                if(this._is_req_body) {
                    String tmpreq = new String(messageInfo.getRequest());
                    String messageBody = new String(tmpreq.substring(reqInfo.getBodyOffset())).trim();
                    messageBody = this.do_encrypt(messageBody, false);
                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setRequest(updateMessage);
                    print_output("PHTM-req", "Final Encrypted Request\n" + new String(updateMessage));
                }
                else if(this._is_ovrr_req_body){
                    String tmpreq = new String(messageInfo.getRequest());
                    String messageBody = new String(tmpreq.substring(reqInfo.getBodyOffset())).trim();
                    messageBody = this.do_encrypt(messageBody, false);
                    
                    if(this._is_ovrr_req_body_form){
                        messageBody = this._req_param[0] + "=" + messageBody;
                    }
                    else if(this._is_ovrr_req_body_json){
                        messageBody = "{\"" + this._req_param[0] + "\":\"" + messageBody + "\"}";
                    }
                    
                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setRequest(updateMessage);
                    print_output("PHTM-req", "Final Encrypted Request\n" + new String(updateMessage));
                }
                else if(this._is_req_param){
                    
                    byte[] _request = messageInfo.getRequest();
                    
                    if(reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON){
                        _request = update_req_params_json(_request, headers, this._req_param, true, false);
                    }
                    else{
                        _request = update_req_params(_request, headers, this._req_param, true, false);                        
                    }
                    print_output("PHTM-req", "Final Encrypted Request\n" + new String(_request));
                    messageInfo.setRequest(_request);
                }
                else {
                    return;
                }
            }
            
            
        }
        else {
            if(this._ignore_response) { return; }
            
            // PHTM Response
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            IResponseInfo resInfo = helpers.analyzeResponse(messageInfo.getResponse());
            String URL = new String(reqInfo.getUrl().toString());
            List headers = resInfo.getHeaders();
            
            
            if(this._host.contains(this.get_host(URL))){
                
                if(this._is_res_body){
                    // Complete Response Body decryption
                    String tmpreq = new String(messageInfo.getResponse());
                    String messageBody = new String(tmpreq.substring(resInfo.getBodyOffset())).trim();
                    messageBody = do_decrypt(messageBody, true);
                    headers.add(this._Header);
                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setResponse(updateMessage);
                    print_output("PHTM-res", "Final Decrypted Response\n" + new String(updateMessage));
                }
                else if(this._is_res_param){
                    // implement left --------------------------
                    byte[] _response = messageInfo.getResponse();
                    
                    _response = this.update_req_params_json(_response, headers, this._res_param, false, true);
                    messageInfo.setResponse(_response);
                    print_output("PHTM-res", "Final Decrypted Response\n" + new String(_response));
                }
                else{
                    return;
                }
                
            }
            
            
        }
    }

    
    
    
    
    
    
    
    
    
}
