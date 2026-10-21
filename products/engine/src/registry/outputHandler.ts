import { OutputRecord } from '../types';

type OutputRecordHandler = (record: Omit<OutputRecord, 'id' | 'timestamp'> & { timestamp?: number }) => void;

let outputRecordHandler: OutputRecordHandler | null = null;

export const setOutputRecordHandler = (handler: OutputRecordHandler | null) => {
  outputRecordHandler = handler;
};

/** The host registers a handler (the web store does at load); without one the record is dropped. */
export const emitOutputRecord = async (record: Omit<OutputRecord, 'id' | 'timestamp'> & { timestamp?: number }) => {
  outputRecordHandler?.(record);
};
