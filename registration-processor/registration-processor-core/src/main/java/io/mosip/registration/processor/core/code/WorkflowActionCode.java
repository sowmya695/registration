package io.mosip.registration.processor.core.code;


// TODO: Auto-generated Javadoc
/**
 * The Enum WorkflowActionCode.
 */
public enum WorkflowActionCode {

	/** The resume processing. */
	RESUME_PROCESSING, 

	/** The resume processing and remove hotlisted tag. */
	RESUME_PROCESSING_AND_REMOVE_HOTLISTED_TAG,

	/** The resume from beginning. */
	RESUME_FROM_BEGINNING,

	/** The resume from beginning and remove hotlisted tag. */
	RESUME_FROM_BEGINNING_AND_REMOVE_HOTLISTED_TAG,

	/** The stop processing. */
	STOP_PROCESSING,

	/** The paused for additional info. */
	PAUSED_FOR_ADDITIONAL_INFO,

	/** The resume parent flow. */
	RESUME_PARENT_FLOW,

	/** The restart parent flow. */
	RESTART_PARENT_FLOW,

	/** The stop and notify. */
	STOP_AND_NOTIFY,

	/** The packet for paused. */
	PACKET_FOR_PAUSED

}
