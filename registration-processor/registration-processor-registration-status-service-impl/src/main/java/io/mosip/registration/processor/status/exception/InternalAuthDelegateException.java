package io.mosip.registration.processor.status.exception;

import io.mosip.kernel.core.exception.BaseCheckedException;
import io.mosip.registration.processor.core.exception.util.PlatformErrorMessages;

/**
 * The Class InternalAuthDelegateException.
 */
public class InternalAuthDelegateException extends BaseCheckedException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 6748760277721155095L;

	/** The id. */
	private String id;

	/**
	 * Gets the id.
	 *
	 * @return the id
	 */
	public String getId() {
		return id;
	}

	/**
	 * Instantiates a new id repo app exception.
	 */
	public InternalAuthDelegateException() {
		super();
	}

	/**
	 * Instantiates a new internal auth delegate exception.
	 *
	 * @param errorCode the error code
	 * @param errorMessage the error message
	 */
	public InternalAuthDelegateException(String errorCode, String errorMessage) {
		super(errorCode, errorMessage);
	}


	/**
	 * Instantiates a new internal auth delegate exception.
	 *
	 * @param errorCode the error code
	 * @param errorMessage the error message
	 * @param rootCause the root cause
	 */
	public InternalAuthDelegateException(String errorCode, String errorMessage, Throwable rootCause) {
		super(errorCode, errorMessage, rootCause);
	}
	

	/**
	 * Instantiates a new internal auth delegate exception.
	 *
	 * @param errorCode the error code
	 * @param errorMessage the error message
	 * @param rootCause the root cause
	 * @param id the id
	 */
	public InternalAuthDelegateException(String errorCode, String errorMessage, Throwable rootCause, String id) {
		super(errorCode, errorMessage, rootCause);
		this.id = id;
	}


	/**
	 * Instantiates a new internal auth delegate exception.
	 *
	 * @param exceptionConstant the exception constant
	 */
	public InternalAuthDelegateException(PlatformErrorMessages exceptionConstant) {
		this(exceptionConstant.getCode(), exceptionConstant.getMessage());
	}


	/**
	 * Instantiates a new internal auth delegate exception.
	 *
	 * @param exceptionConstant the exception constant
	 * @param rootCause the root cause
	 */
	public InternalAuthDelegateException(PlatformErrorMessages exceptionConstant, Throwable rootCause) {
		this(exceptionConstant.getCode(), exceptionConstant.getMessage(), rootCause);
	}
	
	/**
	 * Instantiates a new internal auth delegate exception.
	 *
	 * @param exceptionConstant the exception constant
	 * @param id the id
	 */
	public InternalAuthDelegateException(PlatformErrorMessages exceptionConstant, String id) {
		this(exceptionConstant.getCode(), exceptionConstant.getMessage());
		this.id = id;
	}


	/**
	 * Instantiates a new internal auth delegate exception.
	 *
	 * @param exceptionConstant the exception constant
	 * @param rootCause the root cause
	 * @param id the id
	 */
	public InternalAuthDelegateException(PlatformErrorMessages exceptionConstant, Throwable rootCause, String id) {
		this(exceptionConstant.getCode(), exceptionConstant.getMessage(), rootCause);
		this.id = id;
	}
}
