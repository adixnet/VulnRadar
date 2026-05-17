const handleStartScan = async (targetUrl: string) => {
    setIsScanning(true);
    setScanResults(null);
    setErrorMessage(null);
    
    try {
        const result = await executeScan(targetUrl);
        
        if (result.success) {
            setScanResults(result);
        } else {
            setErrorMessage(result.error); 
        }
    } catch (error: any) {
        setErrorMessage(error.message || "An unexpected system error occurred.");
    } finally {
        setIsScanning(false);
    }
};
