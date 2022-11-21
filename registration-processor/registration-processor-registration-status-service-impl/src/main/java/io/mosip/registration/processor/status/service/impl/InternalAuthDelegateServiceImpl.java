package io.mosip.registration.processor.status.service.impl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.conn.util.DomainType;
import org.bouncycastle.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BIR.BIRBuilder;
import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.constant.ProcessedLevelType;
import io.mosip.kernel.biometrics.constant.PurposeType;
import io.mosip.kernel.biometrics.entities.RegistryIDType;
import io.mosip.kernel.core.cbeffutil.constant.CbeffConstant;
import io.mosip.kernel.core.exception.BiometricSignatureValidationException;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.registration.processor.core.auth.dto.AuthRequestDTO;
import io.mosip.registration.processor.core.auth.dto.AuthResponseDTO;
import io.mosip.registration.processor.core.auth.dto.BioInfo;
import io.mosip.registration.processor.core.auth.dto.DataInfoDTO;
import io.mosip.registration.processor.core.auth.dto.ErrorDTO;
import io.mosip.registration.processor.core.auth.dto.IndividualIdDto;
import io.mosip.registration.processor.core.auth.dto.ResponseDTO;
import io.mosip.registration.processor.core.code.ApiName;
import io.mosip.registration.processor.core.constant.LoggerFileConstant;
import io.mosip.registration.processor.core.exception.ApisResourceAccessException;
import io.mosip.registration.processor.core.exception.ValidationFailedException;
import io.mosip.registration.processor.core.exception.util.PlatformErrorMessages;
import io.mosip.registration.processor.core.http.ResponseWrapper;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.spi.restclient.RegistrationProcessorRestClientService;
import io.mosip.registration.processor.core.status.util.StatusUtil;
import io.mosip.registration.processor.packet.storage.utils.BioSdkUtil;
import io.mosip.registration.processor.rest.client.utils.RestApiClient;
import io.mosip.registration.processor.status.constants.AuthConstants;
import io.mosip.registration.processor.status.exception.DecryptionFailureException;
import io.mosip.registration.processor.status.exception.InternalAuthDelegateException;
import io.mosip.registration.processor.status.service.InternalAuthDelegateService;
import io.mosip.registration.processor.status.utilities.BytesUtil;
import io.mosip.registration.processor.status.utilities.RegistrationSecurityManager;
import lombok.AllArgsConstructor;
import lombok.Data;


/**
 * The Class InternalAuthDelegateServiceImpl - The implementation that delegates
 * the calls to ID-Authentication's internal auth APIs.
 *
 * @author Loganathan.Sekar
 */
@Component
public class InternalAuthDelegateServiceImpl implements InternalAuthDelegateService {
	
	private final Logger logger = RegProcessorLogger.getLogger(InternalAuthDelegateServiceImpl.class);

	private static final String REFERENCE_ID = "referenceId";

	private static final String APPLICATION_ID = "applicationId";
	
	private static final String APPID = "regproc";

	/** The rest api client. */
	@Autowired
	private RestApiClient restApiClient;
	
	@Autowired
	RegistrationProcessorRestClientService<Object> restClientService;

	@Autowired
	@Qualifier("selfTokenRestTemplate")
	private RestTemplate restTemplate;

	
	/** The get certificate uri. */
	@Value("${ida-internal-get-certificate-uri}")
	private String getCertificateUri;
	

	@Value("${internal.reference.id}")
	private String referenceId;
	
	@Value("${internal.biometrics.reference.id}")
	private String biometricsReferenceId;
	

	
	@Autowired
	ObjectMapper mapper;
	
	@Autowired
	RegistrationSecurityManager registrationSecurityManager;
	
	@Autowired
	private BioSdkUtil bioUtil;

	
	/**
	 * Authenticate.
	 *
	 * @param authRequestDTO the auth request DTO
	 * @param headers the headers
	 * @return the AuthResponseDTO
	 * @throws IOException 
	 * @throws ApisResourceAccessException 
	 * @throws InternalAuthDelegateException 
	 * @throws DecryptionFailureException 
	 * @throws Exception 
	 */
	@Override
	public AuthResponseDTO authenticate(AuthRequestDTO authRequestDTO, HttpHeaders headers)   {
		AuthResponseDTO authResponseDTO=new AuthResponseDTO();
		List<ErrorDTO> errors=new ArrayList<>();
		ResponseDTO responseDTO=null;
		// get individualId from userId
		String individualId;
		try {
			individualId = getIndividualIdByUserId(authRequestDTO.getIndividualId());
			Map<String, Object> request= decryptRequest(authRequestDTO);
			List<io.mosip.kernel.biometrics.entities.BIR> birs=decipherBioDataAndgetBir(request);
			bioUtil.authenticateBiometrics(individualId, birs, "", "");
			responseDTO=new ResponseDTO();
			responseDTO.setAuthStatus(true);
			authResponseDTO.setResponse(responseDTO);
		} catch (ApisResourceAccessException | IOException e) {
			updateDtosAndLog(errors,e,PlatformErrorMessages.RPR_RGS_API_RESOUCE_ACCESS_FAILED.getCode(),PlatformErrorMessages.RPR_RGS_API_RESOUCE_ACCESS_FAILED.getMessage());
		} catch (DecryptionFailureException e) {
			updateDtosAndLog(errors,e,PlatformErrorMessages.RPR_RGS_DECRYPTION_EXCEPTION.getCode(),PlatformErrorMessages.RPR_RGS_DECRYPTION_EXCEPTION.getMessage());
		} catch (InternalAuthDelegateException e) {
			updateDtosAndLog(errors,e,PlatformErrorMessages.RPR_RGS_UNABLE_TO_PROCESS_EXCEPTION.getCode(),PlatformErrorMessages.RPR_RGS_UNABLE_TO_PROCESS_EXCEPTION.getMessage());
		} catch (BiometricSignatureValidationException e) {
			updateDtosAndLog(errors,e,PlatformErrorMessages.RPR_RGS_BIOMETRIC_SIGNATURE__VALIDATION_EXCEPTION.getCode(),PlatformErrorMessages.RPR_RGS_BIOMETRIC_SIGNATURE__VALIDATION_EXCEPTION.getMessage());		
		}  catch (ValidationFailedException e) {
			updateDtosAndLog(errors,e,PlatformErrorMessages.RPR_RGS_BIOSDK_EXCEPTION.getCode(),PlatformErrorMessages.RPR_RGS_BIOSDK_EXCEPTION.getMessage());
		}catch (Exception e) {
			updateDtosAndLog(errors,e,PlatformErrorMessages.RPR_RGS_UNABLE_TO_PROCESS_EXCEPTION.getCode(),PlatformErrorMessages.RPR_RGS_UNABLE_TO_PROCESS_EXCEPTION.getMessage());
		}
		finally {
			if(!errors.isEmpty()){
				authResponseDTO.setErrors(errors);
			}
		}
		return authResponseDTO;
	}
	private void updateDtosAndLog(List<ErrorDTO> errors, Exception e, String code, String message) {
		ErrorDTO errorDTO=new ErrorDTO();
		errorDTO.setErrorCode(code);
		errorDTO.setErrorMessage(message);
		errors.add(errorDTO);
		logger.error("Error in Authentication  {} {}", e.getMessage(),
				ExceptionUtils.getStackTrace(e));
		
	}
	private List<io.mosip.kernel.biometrics.entities.BIR> decipherBioDataAndgetBir(Map<String, Object> request) throws JsonMappingException, JsonProcessingException, DecryptionFailureException, ApisResourceAccessException, InternalAuthDelegateException, BiometricSignatureValidationException, io.mosip.kernel.core.util.exception.JsonProcessingException  {
		List<DataInfoDTO> dataInfoDTOList = null;
		Object biometrics = request.get(AuthConstants.BIOMETRICS);
		if (Objects.nonNull(biometrics) && biometrics instanceof List) {
			List<Object> bioIdentity = (List<Object>) biometrics;
			dataInfoDTOList = new ArrayList<DataInfoDTO>();
			for (int i = 0; i < bioIdentity.size(); i++) {
				Object obj = bioIdentity.get(i);
				if (obj instanceof Map) {
					dataInfoDTOList.add(decipherBioData(obj, i));
				}
			}
		}
		List<io.mosip.kernel.biometrics.entities.BIR> birList=new ArrayList();
       for(DataInfoDTO dataInfoDTO:dataInfoDTOList) {
    	   birList.add(getBir(dataInfoDTO.getBioValue(), dataInfoDTO));
	       }
		return birList;
	}

	private DataInfoDTO decipherBioData(Object obj, int index) throws DecryptionFailureException, ApisResourceAccessException, InternalAuthDelegateException, JsonMappingException, JsonProcessingException, BiometricSignatureValidationException, io.mosip.kernel.core.util.exception.JsonProcessingException {

		Map<String, Object> map = (Map<String, Object>) obj;

		Optional<String> dataOpt = getStringValue(map, AuthConstants.DATA);
		verifyBioDataSignature(dataOpt.get(), index);
		try {
			byte[] decodedData = CryptoUtil.decodeURLSafeBase64(extractBioData((String) map.get(AuthConstants.DATA)));
			DataInfoDTO data = mapper.readValue(decodedData, DataInfoDTO.class);

			Object bioValue = data.getBioValue();

			Object sessionKey = Objects.nonNull(map.get(AuthConstants.SESSION_KEY)) ? map.get(AuthConstants.SESSION_KEY) : null;
			Object thumbprint = Objects.nonNull(map.get(AuthConstants.THUMBPRINT)) ? map.get(AuthConstants.THUMBPRINT) : null;
			String timestamp =data.getTimestamp();
			String transactionId = data.getTransactionId();
			byte[] xorBytes = BytesUtil.getXOR(timestamp, transactionId);
			byte[] saltLastBytes = BytesUtil.getLastBytes(xorBytes, AuthConstants.DEFAULT_SALT_LAST_BYTES_NUM);
			String salt = CryptoUtil.encodeToPlainBase64(saltLastBytes);
			byte[] aadLastBytes = BytesUtil.getLastBytes(xorBytes, AuthConstants.DEFAULT_AAD_LAST_BYTES_NUM);
			String aad = CryptoUtil.encodeToPlainBase64(aadLastBytes);
			String decryptedData =internalKernelDecryptAndDecode(String.valueOf(thumbprint), CryptoUtil.decodeURLSafeBase64(String.valueOf(sessionKey)), CryptoUtil.decodeURLSafeBase64(String.valueOf(bioValue)), biometricsReferenceId,
					aad, salt, true,isThumbprintValidationRequired());
			
			data.setBioValue(decryptedData);
			return data;
		} catch (IOException e) {
			throw new InternalAuthDelegateException(PlatformErrorMessages.RPR_RGS_UNABLE_TO_PROCESS_EXCEPTION,e);
		}
	}

	private Map<String, Object> decryptRequest(AuthRequestDTO authRequestDTO) throws DecryptionFailureException, ApisResourceAccessException, InternalAuthDelegateException, JsonMappingException, JsonProcessingException {

		byte[] encryptedRequest=(byte[])decode(authRequestDTO.getRequest());
		byte[] encryptedSessionKey=(byte[])decode(authRequestDTO.getRequestSessionKey());
		String thumbprint = Objects.nonNull(authRequestDTO.getThumbprint())
				? String.valueOf(authRequestDTO.getThumbprint())
				: null;
		
		String 	decryptedAndDecodedData=internalKernelDecryptAndDecode(thumbprint, encryptedSessionKey, encryptedRequest, referenceId, null, null, false, isThumbprintValidationRequired());
		return mapper.readValue(decryptedAndDecodedData, Map.class);

	}

	/**
	 * Gets the certificate.
	 *
	 * @param applicationId the application id
	 * @param referenceId   the reference id
	 * @param headers the headers
	 * @return the certificate
	 * @throws Exception 
	 */
	@Override
	public Object getCertificate(String applicationId, Optional<String> referenceId, HttpHeaders headers) throws Exception {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(getCertificateUri);
		builder.queryParam(APPLICATION_ID, applicationId);
		referenceId.ifPresent(refId -> builder.queryParam(REFERENCE_ID, refId));
		return restApiClient.getApi(builder.build().toUri(), Object.class);
	}
	
	public <T> HttpEntity<T> postApi(String uri, MediaType mediaType, HttpEntity<?> requestEntity, Class<T> responseClass) throws Exception {
		try {
			logger.info(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.APPLICATIONID.toString(),
					LoggerFileConstant.APPLICATIONID.toString(), uri);
			return restTemplate.exchange(uri, HttpMethod.POST, requestEntity, responseClass);
		} catch (Exception e) {
			logger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.APPLICATIONID.toString(),
					LoggerFileConstant.APPLICATIONID.toString(), e.getMessage() + ExceptionUtils.getStackTrace(e));
			restApiClient.tokenExceptionHandler(e);
			throw e;
		}
	}
	
	/**
	 * get the individualId by userid
	 * 
	 * @param userid
	 * @return individualId
	 * @throws ApisResourceAccessException
	 * @throws IOException
	 */
	private String getIndividualIdByUserId(String userid) throws ApisResourceAccessException, IOException {

		logger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.USERID.toString(), userid,
				"InternalAuthDelegateServiceImpl::getIndividualIdByUserId()::entry");
		List<String> pathSegments = new ArrayList<>();
		pathSegments.add(APPID);
		pathSegments.add(userid);
		String individualId = null;
		ResponseWrapper<?> response = null;
		response = (ResponseWrapper<?>) restClientService.getApi(ApiName.GETINDIVIDUALIDFROMUSERID, pathSegments, "",
				"", ResponseWrapper.class);
		logger.debug(
				"getIndividualIdByUserId called for with GETINDIVIDUALIDFROMUSERID GET service call ended successfully");
		if (response.getErrors() != null) {
			throw new ApisResourceAccessException(
					PlatformErrorMessages.LINK_FOR_USERID_INDIVIDUALID_FAILED_STATUS_EXCEPTION.getMessage());
		} else {
			IndividualIdDto readValue = mapper.readValue(mapper.writeValueAsString(response.getResponse()),
					IndividualIdDto.class);
			individualId = readValue.getIndividualId();
		}
		logger.debug("InternalAuthDelegateServiceImpl::getIndividualIdByUserId()::exit{}",userid);
	
		return individualId;
	}
	protected static Object decode(String stringToDecode) throws InternalAuthDelegateException{
		try {
			if (Objects.nonNull(stringToDecode)) {
				return CryptoUtil.decodeURLSafeBase64(stringToDecode);
			} else {
				return stringToDecode;
			}
		} catch (IllegalArgumentException ex) {
			throw new InternalAuthDelegateException(PlatformErrorMessages.RPR_RGS_UNABLE_TO_PROCESS_EXCEPTION,ex);
		}
		
	}
	private String internalKernelDecryptAndDecode(String thumbprint, byte[] encryptedSessionKey,
			byte[] encryptedData, String refId, String aad, String salt,
			Boolean encode, Boolean isThumbprintEnabled) throws DecryptionFailureException, ApisResourceAccessException, InternalAuthDelegateException {
		String decryptedRequest = null;
		byte[] data;
		if (isThumbprintEnabled) {
			data = registrationSecurityManager.combineDataForDecryption(encryptedSessionKey, encryptedData);
			byte[] bytesFromThumbprint = registrationSecurityManager.getBytesFromThumbprint(thumbprint);
			// Compare the thumbprint bytes with starting bytes of data to check if it is already exists
			boolean isThumbprintAlreadyExsists = data.length > bytesFromThumbprint.length 
					&& Arrays.areEqual(bytesFromThumbprint, Arrays.copyOf(data, bytesFromThumbprint.length));
			if(!isThumbprintAlreadyExsists) {
				data = ArrayUtils.addAll(bytesFromThumbprint, data);
			}
		} else {
			data = registrationSecurityManager.combineDataForDecryption(encryptedSessionKey, encryptedData);
		}
			byte[] decryptedIdentity = registrationSecurityManager.decrypt(CryptoUtil.encodeToURLSafeBase64(data), refId, aad, salt,
					isThumbprintEnabled);
			if (encode) {
				decryptedRequest = CryptoUtil.encodeToPlainBase64(decryptedIdentity);
			} else {
				decryptedRequest = new String(decryptedIdentity, StandardCharsets.UTF_8);
			}
	
		return decryptedRequest;
	}
	private final boolean isThumbprintValidationRequired() {
		//After integration with 1.1.5.1 version of keymanager, thumbprint is always mandated for decryption.
		return true;
	}
	/**
	 * Gets the string value.
	 *
	 * @param map       the biometric data
	 * @param fieldName the field name
	 * @return the string value
	 */
	private Optional<String> getStringValue(Map<String, Object> map, String fieldName) {
		return Optional.ofNullable(map.get(fieldName)).filter(obj -> obj instanceof String).map(obj -> (String) obj);
	}
	private void verifyBioDataSignature(String jwsSignature, int index) throws JsonMappingException, JsonProcessingException, ApisResourceAccessException, BiometricSignatureValidationException, io.mosip.kernel.core.util.exception.JsonProcessingException {
		if (!registrationSecurityManager.verifySignature(jwsSignature,"Device")) {
			logger.error("Invalid certificate in biometrics>data");
			throw new BiometricSignatureValidationException(StatusUtil.BIOMETRICS_SIGNATURE_VALIDATION_FAILURE.getCode(),
					StatusUtil.BIOMETRICS_SIGNATURE_VALIDATION_FAILURE.getMessage()+"request/biometrics/" + index + "/data");
		}
	}
	
	private String extractBioData(String dataFieldValue) {
		return getPayloadFromJwssignature(dataFieldValue);
	}
	private String getPayloadFromJwssignature(String jws) {
		String[] split = jws.split("\\.");
		if (split.length >= 2) {
			return split[1];
		}
		return jws;
	}
	/**
	 * To create BIRType based on requested input.
	 *
	 * @param info            the info
	 * @param type the type
	 * @return the bir
	 */
	private BIR getBir(Object info, DataInfoDTO dataInfoDTO) {
		BIRBuilder birBuilder = new BIRBuilder();
		if (info instanceof String) {
			RegistryIDType format = new RegistryIDType();
			format.setOrganization(String.valueOf(CbeffConstant.FORMAT_OWNER));
			format.setType(dataInfoDTO.getBioType());
			BDBInfo bdbInfo = new BDBInfo.BDBInfoBuilder()
					.withType(Collections.singletonList(getBiometricType(dataInfoDTO.getBioType())))
					.withSubtype(java.util.Arrays.asList(dataInfoDTO.getBioSubType()))
					.withLevel(ProcessedLevelType.fromValue(AuthConstants.BDB_DEAULT_PROCESSED_LEVEL))
					.withFormat(format)
					.withPurpose(PurposeType.VERIFY).build();
			String reqInfoStr = (String) info;
			byte[] decodedrefInfo = CryptoUtil.decodePlainBase64(reqInfoStr);
			birBuilder.withBdb(decodedrefInfo);
			birBuilder.withBdbInfo(bdbInfo);
		}
		return birBuilder.build();
	}

	private static BiometricType getBiometricType(String type) {
		if (isInEnum(type, BiometricType.class)) {
			return BiometricType.valueOf(type);
		} else {
			switch (type) {
			case "FMR":
				return BiometricType.FINGER;
			default:
				return BiometricType.fromValue(type);
			}
		}
	}
	public static <E extends Enum<E>> boolean isInEnum(String value, Class<E> enumClass) {
		for (E e : enumClass.getEnumConstants()) {
			if (e.name().equals(value)) {
				return true;
			}
		}
		return false;
	}

}
