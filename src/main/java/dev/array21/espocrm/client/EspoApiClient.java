package dev.array21.espocrm.client;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;

import dev.array21.espocrm.Serializer;
import dev.array21.espocrm.types.Method;
import dev.array21.espocrm.types.Params;
import dev.array21.httplib.Http;
import dev.array21.httplib.Http.MediaFormat;
import dev.array21.httplib.Http.RequestMethod;
import dev.array21.httplib.Http.ResponseObject;

/**
 * A client for the EspoCRM API
 * @author Tobias de Bruijn
 * @since 1.0.0
 */
public class EspoApiClient {
	protected String url, username, password, apiKey, secretKey;
	private final String urlPath = "/api/v1/";
	private final Gson gson = new Gson();
	
	private String normalizeUrl(String action) {
		return String.format("%s%s%s", this.url, this.urlPath, action);
	}
	
	/**
	 * Send a GET request to EspoCRM
	 * @param action The action (i.e URL path)
	 * @param params The parameters to use
	 * @return Returns the JSON response
	 * @throws InvalidKeyException Thrown only when using HMAC authorization, if the key is invalid
	 * @throws IOException
	 * @throws RequestException
	 */
	public String requestGet(String action, Params params) throws InvalidKeyException, IOException, RequestException {
		return this.request(Method.GET, action, params, null);
	}
	
	/**
	 * Send a POST, PUT or DELETE request to EspoCRM
	 * @param <T> The type of payload, this will be serialized using Google's GSON
	 * @param method The request method
	 * @param action The action (i.e URL path)
	 * @param payload The payload to send along with the request. This will be serialized using Google's GSON
	 * @return Returns the JSON response
	 * @throws InvalidKeyException Thrown only when using HMAC authorization, if the key is invalid
	 * @throws IOException
	 * @throws RequestException
	 */
	public <T> String request(Method method, String action, T payload) throws InvalidKeyException, IOException, RequestException {
		return this.request(method, action, null, payload);
	}
	
	private <T> String request(Method method, String action, Params params, T payload) throws InvalidKeyException, IOException, RequestException {
		String url = normalizeUrl(action);
		
		if(params != null && method != Method.POST) {
			url = String.format("%s?%s", url, Serializer.serialize(params));
		}
		
		HashMap<String, String> headers = new HashMap<>();
		
		if(this.username != null && this.password != null) {
			String authString = URLEncoder.encode(String.format("%s:%s", this.username, this.password), StandardCharsets.UTF_8);
			headers.put("Authorization", String.format("Basic %s", Base64.getEncoder().encodeToString(authString.getBytes())));

		} else if(this.apiKey != null && this.secretKey != null) {
			headers.put("X-Hmac-Authorization", getHmacAuthorization(method, action));
		
		} else if(this.apiKey != null && this.secretKey == null) {
			headers.put("X-Api-Key", this.apiKey);
		}
		
		ResponseObject responseObject;
		
		//TODO Test for the DELETE endpoint
		if(payload != null && method != Method.GET) {
			responseObject = new Http().makeRequest(toRequestMethod(method), url, null, MediaFormat.JSON, this.gson.toJson(payload), headers);
		} else {
			responseObject = new Http().makeRequest(toRequestMethod(method), url, null, null, null, headers);
		}
		
		if(responseObject.getResponseCode() != 200) {
			throw new RequestException(responseObject.getResponseCode(), responseObject.getConnectionMessage());
		}
		
		return responseObject.getMessage();
	}
	
	private String getHmacAuthorization(Method method, String path) throws InvalidKeyException {
		//Setup the hashing algorithm
		Mac sha256_HMAC = null;
		try {
			sha256_HMAC = Mac.getInstance("HmacSHA256");
			SecretKeySpec secretKey = new SecretKeySpec(this.secretKey.getBytes(), "HmacSHA256");
			sha256_HMAC.init(secretKey);
		} catch (NoSuchAlgorithmException e) {
			// We don't need to handle this exception, since the `HmacSHA256` algorithm is always there
		}
		
		//Get the hash
		//Compose of (method + ' /' + path)
		//Where method: GET, POST etc
		//Where path: Account, Contact etc
		byte[] hash = sha256_HMAC.doFinal((method.toString() + " /" + path).getBytes());
		
		//Compose the final list of Bytes
		//Compose of apiKey + ':' + hash
		//String#getBytes() returns a byte[], so we first have to turn it into
		//a Byte[], then put it in a List<Byte> before we can add it.
		List<Byte> hmacBytes = new ArrayList<>();
		hmacBytes.addAll(Arrays.asList(toObject((this.apiKey + ":").getBytes())));
		hmacBytes.addAll(Arrays.asList(toObject(hash)));
		
		//Get the final hmacAuthorization value
		//First turn the hmacBytes<Byte> into a byte[],
		//Then encode it as base64
		String hmacAuthorization = Base64.getEncoder().encodeToString(toPrimitive(hmacBytes.toArray(new Byte[0])));
		
		//Finally return that base64 String
		return hmacAuthorization;
	}
	
	/**
	 * Convert a byte[] to a Byte[]
	 * @param array The input byte[]
	 * @return The Byte[] output. Returns null if the input array is null
	 */
    private static Byte[] toObject(final byte[] array) {
        if (array == null) {
            return null;
        } else if (array.length == 0) {
            return new Byte[0];
        }
        
        final Byte[] result = new Byte[array.length];
        for (int i = 0; i < array.length; i++) {
            result[i] = Byte.valueOf(array[i]);
        }
        return result;
    }
    
    /**
     * Convert a Byte[] to a byte[]
     * @param array The input Byte[]
     * @return The output byte[]. Returns null if the provided input is null
     */
    private static byte[] toPrimitive(final Byte[] array) {
        if (array == null) {
            return null;
        } else if (array.length == 0) {
            return new byte[0];
        }
        
        final byte[] result = new byte[array.length];
        for (int i = 0; i < array.length; i++) {
            result[i] = array[i].byteValue();
        }
        return result;
    }
    
    /**
     * Convert our {@link Method} to HttpLib's {@link RequestMethod}
     * @param method The Method
     * @return The associated RequestMethod, or null if the input does not map to a RequestMethod
     */
    private RequestMethod toRequestMethod(Method method) {
    	switch(method) {
	    	case GET: return RequestMethod.GET;
			case DELETE: return RequestMethod.DELETE;
			case POST: return RequestMethod.POST;
			case PUT: return RequestMethod.PUT;
			default: 
				return null;
    	}
    }
}
