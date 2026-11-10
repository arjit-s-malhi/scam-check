let workerInstance = null;
let isInitializing = false;

/**
 * Lazy loads Tesseract worker only when the Screenshot tab is accessed.
 * Image never leaves the device.
 */
export async function extractTextFromImage(imageSource, onProgress) {
  try {
    if (!workerInstance && !isInitializing) {
      isInitializing = true;
      if (onProgress) onProgress({ status: 'Loading OCR engine...', progress: 0.1 });

      const { createWorker } = await import('tesseract.js');
      workerInstance = await createWorker('eng', 1, {
        logger: m => {
          if (onProgress && m) {
            let label = m.status || 'Processing image...';
            if (m.status === 'recognizing text') {
              label = `Recognizing text (${Math.round((m.progress || 0) * 100)}%)...`;
            } else if (m.status === 'loading language traineddata') {
              label = 'Loading language model...';
            }
            onProgress({ status: label, progress: m.progress ?? 0.5 });
          }
        }
      });
      isInitializing = false;
    }

    if (onProgress) onProgress({ status: 'Scanning image locally...', progress: 0.8 });

    const ret = await workerInstance.recognize(imageSource);
    const text = ret?.data?.text || '';

    if (onProgress) onProgress({ status: 'Complete', progress: 1.0 });
    return {
      success: true,
      text: text.trim(),
      confidence: ret?.data?.confidence || 0
    };
  } catch (err) {
    console.error('OCR Error:', err);
    return {
      success: false,
      text: '',
      error: err.message || 'Failed to scan image locally.'
    };
  }
}

/**
 * Terminate worker when cleaning up
 */
export async function terminateOcrWorker() {
  if (workerInstance) {
    await workerInstance.terminate();
    workerInstance = null;
  }
}

