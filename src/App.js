import { useCallback, useState } from 'react';
import { Grid, Container, Typography, TextField, Button, Divider } from '@mui/material'
import hmacSha1 from 'crypto-js/hmac-sha1';
import {Buffer} from 'buffer';

import './index.css';

function App() {
  const [streamURL, setStreamURL] = useState('');
  const [signedPolicyKey, setSignedPolicyKey] = useState('');
  const [ip, setIp] = useState('');
  const [signedPolicy, setSignedPolicy] = useState('');

  const generatePolicy = useCallback(() => {
    try {
      const policy = {
        allow_ip: ip,
      };
  
      const stringPolicy = JSON.stringify(policy);
      let base64Policy = Buffer.from(stringPolicy).toString('base64');
      base64Policy = base64Policy.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  
      const url = new URL(streamURL);
      const protocolPorts = {
        'http': 80,
        'https': 443,
        'rtmp': 1935,
        'wss': 433,
        'ws': 80,
      };
  
      const protocol = url.protocol.replace(':', '');
      const port = url.port || protocolPorts[protocol];
      const resource = `${protocol}://${url.hostname}:${port}${url.pathname}?policy=${base64Policy}`;
  
      const signature = hmacSha1(base64Policy, signedPolicyKey).toString();
      const base64Signature = Buffer.from(signature).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  
      const signedPolicy = `${resource}&signature=${base64Signature}`;
  
      setSignedPolicy(signedPolicy);
    } catch (error) {
      setSignedPolicy(`Error: ${error.message}`)
    }
  }, [streamURL, ip, signedPolicyKey]);

  return (
    <Container>
      <Typography variant="h2">
        Signed Policy Generator
      </Typography>

      <Grid container spacing={2} padding={2}>
        <Grid item sm={6}>
          <TextField
            label="Stream URL"
            type="url"
            value={streamURL}
            onChange={(e) => setStreamURL(e.target.value)}
            fullWidth
          />
        </Grid>
        <Grid item sm={6}>
          <TextField
            label="Signed Policy Key"
            type="text"
            value={signedPolicyKey}
            onChange={(e) => setSignedPolicyKey(e.target.value)}
            fullWidth
          />
        </Grid>

        <Grid item sm={3}>
          <TextField
            label="Allow IP"
            type="text"
            fullWidth
            value={ip}
            onChange={(e) => setIp(e.target.value)}
          />
        </Grid>

        <Grid item sm={12} container justifyContent="center">
          <Button onClick={generatePolicy} variant="contained" color="primary">
            Generate
          </Button>
        </Grid>

        <Grid item xs={12}>
          <Divider />
        </Grid>

        <Grid item xs={12}>
          <TextField
            label="Signed Policy"
            multiline
            fullWidth
            value={signedPolicy}
            error={signedPolicy.startsWith('Error')}
          />
        </Grid>
      </Grid>

    </Container>
  );
}

export default App;
