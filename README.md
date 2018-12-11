# Python-RADIUS-Server
RADIUS server based in RFC 2865

## Previus Step:

  - Install mongodb 
      ```sh
      $ sudo apt-get install mongodb
      ```
  - Create a mongo collection.
  - Insert your user's credentials in hash format to validate them.
  
## RADIUS Server
  
The server is based in RFC 2865. It needs a shared secret to correct access. It's important to know that this shared secret is in address.yml file, so it's necessary manage the file security correctly. That is, make sure that only this program and administrator users have the necessary permissions to read or write in the file. 
