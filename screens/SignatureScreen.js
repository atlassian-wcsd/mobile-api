import React, { useState, useCallback } from 'react';
import { View, StyleSheet, Alert } from 'react-native';
import SignatureCanvas from '../components/SignatureCanvas';
import { saveSignature } from '../utils/signatureUtils';

const SignatureScreen = () => {
  const [signature, setSignature] = useState(null);

  const handleSaveSignature = useCallback((signatureData) => {
    setSignature(signatureData);
    Alert.alert('Success', 'Signature saved successfully!');
  }, []);

  return (
    <View style={styles.container}>
      <View style={styles.canvasContainer}>
        <SignatureCanvas
          width={350}
          height={200}
          strokeColor="#000000"
          strokeWidth={2}
          onSave={handleSaveSignature}
        />
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#ffffff',
    padding: 20,
  },
  canvasContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#f8f8f8',
    borderRadius: 8,
    padding: 10,
    shadowColor: '#000',
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
    elevation: 5,
  },
});

export default SignatureScreen;