package io.mosip.registration.processor.status.constants;

public class AuthConstants {
	/**
	 * Private Constructor for this class
	 */
	private AuthConstants() {

	}

	public static final String BIOMETRICS = "biometrics";
	public static final String DATA = "data";
	/** The Constant SESSION_KEY. */
	public static final String SESSION_KEY = "sessionKey";
	/** The Constant BIO_VALUE. */
	public static final String BIO_VALUE = "bioValue";
	public static final String THUMBPRINT = "thumbprint";
	
	/** The Constant DEFAULT_AAD_LAST_BYTES_NUM. */
	public static final int DEFAULT_AAD_LAST_BYTES_NUM = 16;

	/** The Constant DEFAULT_SALT_LAST_BYTES_NUM. */
	public static final int DEFAULT_SALT_LAST_BYTES_NUM = 12;
	
	public static final String BDB_DEAULT_PROCESSED_LEVEL = "Raw";


}
