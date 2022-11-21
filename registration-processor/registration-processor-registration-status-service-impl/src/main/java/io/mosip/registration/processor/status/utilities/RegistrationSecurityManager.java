package io.mosip.registration.processor.status.utilities;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Objects;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.core.exception.BaseUncheckedException;
import io.mosip.kernel.core.exception.BiometricSignatureValidationException;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.registration.processor.core.code.ApiName;
import io.mosip.registration.processor.core.constant.LoggerFileConstant;
import io.mosip.registration.processor.core.exception.ApisResourceAccessException;
import io.mosip.registration.processor.core.exception.PacketDecryptionFailureException;
import io.mosip.registration.processor.core.exception.util.PlatformErrorMessages;
import io.mosip.registration.processor.core.http.ResponseWrapper;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.packet.dto.JWTSignatureVerifyRequestDto;
import io.mosip.registration.processor.core.packet.dto.JWTSignatureVerifyResponseDto;
import io.mosip.registration.processor.core.spi.restclient.RegistrationProcessorRestClientService;
import io.mosip.registration.processor.core.status.util.StatusUtil;
import io.mosip.registration.processor.packet.manager.decryptor.DecryptorImpl;
import io.mosip.registration.processor.packet.manager.exception.PacketDecryptionFailureExceptionConstant;
import io.mosip.registration.processor.status.constants.AuthConstants;
import io.mosip.registration.processor.status.dto.CryptomanagerRequestDto;
import io.mosip.registration.processor.status.dto.CryptomanagerResponseDto;
import io.mosip.registration.processor.status.exception.DecryptionFailureException;
import io.mosip.registration.processor.status.exception.InternalAuthDelegateException;

@Component
public class RegistrationSecurityManager {
	
	
	@Value("${mosip.kernel.data-key-splitter}")
	private String keySplitter;
	
	@Value("${mosip.ida.auth.appId}")
	private String appid;
	
	@Autowired
	private Environment env;
	
	@Autowired
	private RegistrationProcessorRestClientService<Object> restClientService;
	
	@Autowired
	private ObjectMapper mapper;
	
	/** The sign applicationid. */
	@Value("${mosip.sign.applicationid:KERNEL}")
	private String signApplicationid;

	/** The sign refid. */
	@Value("${mosip.sign.refid:SIGN}")
	private String signRefid;
	
	private static final String DECRYPT_SERVICE_ID = "mosip.registration.processor.crypto.decrypt.id";
	private static final String REG_PROC_APPLICATION_VERSION = "mosip.registration.processor.application.version";
	private static final String DATETIME_PATTERN = "mosip.registration.processor.datetime.pattern";
	private static final String KEY = "data";
	
	private static Logger regProcLogger = RegProcessorLogger.getLogger(RegistrationSecurityManager.class);
	
	public static byte[] getBytesFromThumbprint(String thumbprint) throws InternalAuthDelegateException {
		try {
			//First try decoding with hex
			return decodeHex(thumbprint);
		} catch (DecoderException e) {
			try {
				//Then try decoding with base64
				return CryptoUtil.decodeURLSafeBase64(thumbprint);
			} catch (Exception ex) {
				throw new InternalAuthDelegateException(PlatformErrorMessages.RPR_RGS_UNABLE_TO_PROCESS_EXCEPTION,ex);
			}
		}
	}
	
	/**
	 * Decode hex.
	 *
	 * @param hexData the hex data
	 * @return the byte[]
	 * @throws DecoderException the decoder exception
	 */
	public static byte[] decodeHex(String hexData) throws DecoderException{
        return Hex.decodeHex(hexData);
    }

	public byte[] combineDataForDecryption(byte[] encryptedSessionKey, byte[] encryptedData) {
		return CryptoUtil.combineByteArray(encryptedData, encryptedSessionKey, keySplitter);
	}

	public byte[] decrypt(String dataToDecrypt, String refId, String aad, String saltToDecrypt,
			Boolean isThumbprintEnabled) throws DecryptionFailureException, ApisResourceAccessException {
		byte[] decryptedData=null;
		try {
			io.mosip.kernel.core.http.RequestWrapper<CryptomanagerRequestDto> request = new RequestWrapper<>();
			CryptomanagerRequestDto cryptomanagerRequestDto = new CryptomanagerRequestDto();
			cryptomanagerRequestDto.setApplicationId(appid);
			cryptomanagerRequestDto.setTimeStamp(DateUtils.getUTCCurrentDateTime());
			cryptomanagerRequestDto.setData(dataToDecrypt);
			cryptomanagerRequestDto.setReferenceId(refId);
			cryptomanagerRequestDto.setAad(aad);
			cryptomanagerRequestDto.setSalt(saltToDecrypt);

			request.setId(env.getProperty(DECRYPT_SERVICE_ID));
			request.setMetadata(null);
			request.setRequest(cryptomanagerRequestDto);
			DateTimeFormatter format = DateTimeFormatter.ofPattern(env.getProperty(DATETIME_PATTERN));
			LocalDateTime localdatetime = LocalDateTime
					.parse(DateUtils.getUTCCurrentDateTimeString(env.getProperty(DATETIME_PATTERN)), format);
			request.setRequesttime(localdatetime);
			request.setVersion(env.getProperty(REG_PROC_APPLICATION_VERSION));
			ResponseWrapper<CryptomanagerResponseDto> response = (ResponseWrapper<CryptomanagerResponseDto>) restClientService
					.postApi(ApiName.CRYPTOMANAGERDECRYPT, "", "", request, ResponseWrapper.class);
			if (response.getResponse() != null) {
				LinkedHashMap responseMap = mapper.readValue(mapper.writeValueAsString(response.getResponse()),
						LinkedHashMap.class);
				 decryptedData = CryptoUtil.decodeURLSafeBase64(responseMap.get(KEY).toString());

			} else {
				regProcLogger.error("Decryption Failure {}",response.getErrors().get(0).getMessage());
                throw new DecryptionFailureException(response.getErrors().get(0).getErrorCode(),
				response.getErrors().get(0).getMessage());	
			}
		} catch (DateTimeParseException e) {
			regProcLogger.error("Decryption Failure  {} {}", e.getMessage(),
					ExceptionUtils.getStackTrace(e));
			throw new DecryptionFailureException(PlatformErrorMessages.RPR_RGS_DATE_TIME_EXCEPTION.getCode(),
					PlatformErrorMessages.RPR_RGS_DATE_TIME_EXCEPTION.getMessage());
		} catch (ApisResourceAccessException e) {
			regProcLogger.error("Decryption Failure  {} {}", e.getMessage(),
					ExceptionUtils.getStackTrace(e));
			if (e.getCause() instanceof HttpClientErrorException) {
				HttpClientErrorException httpClientException = (HttpClientErrorException) e.getCause();
				  throw new DecryptionFailureException(PlatformErrorMessages.RPR_RGS_DECRYPTION_EXCEPTION.getCode(),
						  httpClientException.getResponseBodyAsString());	
			} else {
				throw e;
			}
		}
		catch (Exception e) {
			regProcLogger.error("Decryption Failure  {} {}", e.getMessage(),
					ExceptionUtils.getStackTrace(e));
			throw new DecryptionFailureException(PlatformErrorMessages.RPR_RGS_DECRYPTION_EXCEPTION.getCode(),
					PlatformErrorMessages.RPR_RGS_DECRYPTION_EXCEPTION.getMessage());
		}
		return decryptedData;
	}
	/**
	 * Verify signature.
	 *
	 * @param signature the signature
	 * @param domain the domain
	 * @param requestData the request data
	 * @param isTrustValidationRequired the is trust validation required
	 * @return true, if successful
	 * @throws ApisResourceAccessException 
	 * @throws JsonProcessingException 
	 * @throws JsonMappingException 
	 * @throws BiometricSignatureValidationException 
	 * @throws io.mosip.kernel.core.util.exception.JsonProcessingException 
	 */
	public boolean verifySignature(String signature, String domain)throws ApisResourceAccessException, JsonMappingException, JsonProcessingException, BiometricSignatureValidationException, io.mosip.kernel.core.util.exception.JsonProcessingException {
		JWTSignatureVerifyRequestDto jwtSignatureVerifyRequestDto = new JWTSignatureVerifyRequestDto();
		jwtSignatureVerifyRequestDto.setApplicationId(signApplicationid);
		jwtSignatureVerifyRequestDto.setReferenceId(signRefid);
		jwtSignatureVerifyRequestDto.setActualData(signature.split("\\.")[1]);
		jwtSignatureVerifyRequestDto.setJwtSignatureData(signature);
		jwtSignatureVerifyRequestDto.setValidateTrust(false);
		jwtSignatureVerifyRequestDto.setDomain(domain);
		RequestWrapper<JWTSignatureVerifyRequestDto> request = new RequestWrapper<>();

		request.setRequest(jwtSignatureVerifyRequestDto);
		request.setVersion("1.0");
		DateTimeFormatter format = DateTimeFormatter.ofPattern(env.getProperty(DATETIME_PATTERN));
		LocalDateTime localdatetime = LocalDateTime
				.parse(DateUtils.getUTCCurrentDateTimeString(env.getProperty(DATETIME_PATTERN)), format);
		request.setRequesttime(localdatetime);
		ResponseWrapper<?> responseWrapper = (ResponseWrapper<?>) restClientService
				.postApi(ApiName.JWTVERIFY, "", "", request, ResponseWrapper.class);
		JWTSignatureVerifyResponseDto jwtResponse;
		if (responseWrapper.getResponse() != null) {
			 jwtResponse = mapper.readValue(
					mapper.writeValueAsString(responseWrapper.getResponse()), JWTSignatureVerifyResponseDto.class);

			if (!jwtResponse.isSignatureValid()) {
				regProcLogger.error("Signature Validation failed request:response {} {}", JsonUtils.javaObjectToJsonString(request),
						 JsonUtils.javaObjectToJsonString(responseWrapper));
				
				throw new BiometricSignatureValidationException(
						StatusUtil.BIOMETRICS_SIGNATURE_VALIDATION_FAILURE.getCode(),
						StatusUtil.BIOMETRICS_SIGNATURE_VALIDATION_FAILURE.getMessage());
			}
		} else {
			throw new BiometricSignatureValidationException(responseWrapper.getErrors().get(0).getErrorCode(),
					responseWrapper.getErrors().get(0).getMessage());
		}

		return jwtResponse.isSignatureValid();
	}
}
