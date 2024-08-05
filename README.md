# Access Manager

This is a docker container that manages user authentication and authorization to various resources.</br>
When in production this container only exposes one endpoint, /refresh_state, which fetches the state from azure storage.</br>
So the only way of changing state is to:</br>

1. run this image locally
2. execute the changes
3. update the state stored in azure (currently done manually)
4. call /refresh_state

Its designed this way to prevent unauthorized remote control, as long as azure storage asremain safe/unknown.
