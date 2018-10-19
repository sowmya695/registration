package io.mosip.kernel.datamapper.orika.exception;

import io.mosip.kernel.core.exception.BaseUncheckedException;

/**
 * 
 * Custom class for DataMapper Exception
 * 
 * @author Neha
 * @since 1.0.0
 *
 */
public class DataMapperException extends BaseUncheckedException {

	/**
	 * Generated serialVersionUID
	 */
	private static final long serialVersionUID = 2L;

	/**
	 * Constructor for DataMapperException
	 * 
	 * @param errorCode
	 *            The error code
	 * @param errorMessage
	 *            The error message
	 */
	public DataMapperException(String errorCode, String errorMsg) {
		super(errorCode, errorMsg);
	}

	/**
	 * Constructor for DataMapperException
	 * 
	 * @param errorMsg
	 *            The error message
	 */
	public DataMapperException(String errorMsg) {
		super(errorMsg);
	}

}
