**Install Dependencies**
```
$ npm install prompt, jsonfile
```

**Running the  Example**

```bash
cd listeners

# terminal 1

# Create PayPal Entity.

# Follow prompts.
# prompt: Enter location to save entity credentials: .
# prompt: entity: PayPal
# prompt: Password: PayPal
node ../../install.js

# Create PayPalRedirect Entity.

# Follow prompts.
# prompt: Enter location to save entity credentials: .
# prompt: entity: PayPalRedirect
# prompt: Password: PayPalRedirect
node ../../install.js

# Start listening to seif connections
# Follow prompts and use PayPal as the entity.
# prompt: entity: PayPal
# prompt: Password: PayPal
node listener.js
```

```bash
# Terminal 2

cd listeners

# Start listening to seif connections
# Follow prompts and use PayPalRedirect as the entity.
# prompt: entity: PayPalRedirect
# prompt: Password: PayPalRedirect
node redirectListener.js
```

```bash
# Terminal 3

cd initiator

# Create user Entity.

# Follow prompts.
# prompt: Enter location to save entity credentials: .
# prompt: entity: user
# prompt: Password: user
node ../../install.js

# Follow prompts and use user as the entity.
# prompt: entity: user
# prompt: Password: user
node initiator.js
```
