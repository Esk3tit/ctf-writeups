# chatwurst

## by *kaipan*

### Description

We are presented with a mobile chatting/messaging app, and we are tasked with finding the flag in a private conversation between a user named *FizzbuzzMcFlurry* and one or more other persons who we don't really care about. We are given an APK file (mobile app file) that we need to decompile. We use **jadx** (**jadx-gui** version) since it has a nice decompiler GUI for us to easily look at the decompiled Java code for the mobile app.

### Understanding the App

All of the important code can be found in `Source code > com > sinclustoapps.chatwurst`. We start with the `MainActivity` code file. After analyzing we see that this is just for signing in with an existing account or registering a brand new account. We notice that the functions for managing the accounts call other functions from within the `ChatwurstClient` code file. Upon investigating this decompiled code file, we see that all the functions in here make API calls/requests to the backend that manages all the data (and has the messages of the target user we want to access). This file is the most important one here, but I'll quickly go over the other two sorta important files for understanding how the entire mobile app works: `ChatGroupsActivity`, `CreateGroupActivity`, and `TextChatActivity`. The first manages the creation and loading of the chat groups that the user is in after logging in (these are the conversations that include the logged in user as a participant) by getting data from the backend. The second manages the creation of new groups/conversations on the backend, and includes functionality for adding users to the conversation (like adding users to a DM on Discord). Lastly, `TextChatActivity` is for actually sending messages after you choose a conversation/group to chat in. This module is for loading messages that others have sent in the group and handles the creation of your own messages that you send to the group as well by getting and adding data to the backend.

Going back to `ChatwurstClient`, we can surmise that in order to get the messages from *FizzbuzzMcFlurry* that contains the flag, we first have to find the group that contains the message by making an API call (`getGroups`) which retrieves all the groups for a particular hidden user ID, and then we need to access that group's messages by making an API call (`getMessages`). Then we should get the data returned in JSON with all of the messages and we just need to look through the messages and find the flag. We aren't creating groups or sending messages, so we can ignore those respective API calling functions in the decompiled code. 

### Exploit

The code indicates that the app makes POST requests to the backend to retrieve and send data, so we use an API tester like *ReqBin* or *Postman* to send POST requests to the endpoint as well just like the app, so we can retrieve and send the same information that the app sends to get the group ID and messages as responses back from the backend to analyze. One thing to note is the types of data that the app sends to retrieve the group ID and messages. For getting the group ID's for a particular user, we need to send a dictionary, which itself contains a `credential` dictionary, and this dictionary contains a `username` and `password` key presumably for the username and password of the current user for validation on the backend; additionally, we need to send the `user_id` key-value pair as well for the internal/hidden user ID we want to get all the groups/conversations for. For getting messages it is mostly the same as we need a `credential` dictionary within our JSON object to send to the endpoint (containing `username` and `password`) but rather than sending `user_id` we instead send `group_id` (also internal ID not visible to end user) so that we can get all messages corresponding to that uniquely identified group or conversation. Also, note that there isn't any validation done on the credentials against the user ID or group ID. That is, we don't check if the `username` and `password` actually match the account tied to a particular user ID or group ID (testing indicates that it checks if the credentials and user ID are valid on their own, but not together). This means that we can enter any valid credentials but then send any arbitrary user ID to the get group ID endpoint even if the user ID doesn't belong to the credentials we send. Same goes for getting messages as the group ID that we send may not have the credentials that we send alongside it as a participant in the group because no verification is done to make sure that we can only send credentials that correspond to the correct user ID or belongs to the group indicated by the group ID.

We can then get arbitrary access to any group and its messages as long as we have a valid as long as we have a valid account and know the  target internal user ID and/or group ID. The former can easily be done by creating a new (valid) account, and then latter takes some trial and error for getting the user ID, but we can go about it a more efficient way (and group ID can be obtained once we have user ID).

The first step is then to create a new account to get a set of credentials that we can use as explained prior, and we can also take this opportunity to gain more information on how user IDs are assigned to accounts (incremental or random?).

We send the following POST request to the http://chatwurst.ctf-league.osusec.org/create_user endpoint using *ReqBin* (or *Postman*)

```json
{
    "username": "Bruh3",
    "password": "ihateithere"
}
```

Since we are creating an account, you can choose your username and password values for the JSON object we send, but the function in the decompiled code indicates that we need to have the keys `username` and `password` specifically in our dictionary that gets converted to a JSON object.

We get the following response:

```json
{
    "user_id": 25
}
```

Your user ID will vary, but we create a few more accounts using the same POST request structure earlier and discover that user IDs are assigned incrementally, so we need to work backwards in user IDs to find the ID of our target. Of course, we can reason that the target account has been on the platform longer than we have, so his account must have a smaller user ID, and we choose to start checking from 0 or 1 and start going up in user IDs. We try out a variety of user IDs to guess the ID of *FizzbuzzMcFlurry* with the get groups endpoint since it takes a user ID as part of the JSON object we send to the endpoint. IDs could start at 0 or 1, so you probably should check both, but for the sake of brevity I'll just mention the correct IDs from here on out.

In this case, the user ID that belongs to *FizzbuzzMcFlurry* is 1. We know because the request to the http://chatwurst.ctf-league.osusec.org/get_groups endpoint using our valid account credentials that we created and we get a valid response back with all the group IDs and the participants in the group associated with the ID.

POST request:

```json
{
  "credential": 
 {
   "username": "Bruh3", 
   "password": "ihateithere"
 }, 
 "user_id": 1
}
```

Of course, the `credential` dictionary can contain any valid credentials. Since the backend doesn't seem to work as of the writing of this writeup, I'm gonna save myself the trouble and not type out the exact response, but we get back all the group IDs of the groups that include the user with ID 1 (involve *FizzbuzzMcFlurry*):

`1, 2, 3, 9, 10`

We now need to use the get messages endpoint at http://chatwurst.ctf-league.osusec.org/get_messages to try out all of the group IDs to get all the messages for each of the groups/conversations, and then look for the flag within that group/conversation. Once again for brevity, the group/conversation that contains the flag is the group/conversation with the ID 9. The POST request is as follows (once again, `credential` can be any valid set of credentials):

```json
{
  "credential": 
 {
   "username": "Bruh3", 
   "password": "ihateithere"
 }, 
 "group_id": 9
}
```

The server gives us back a response with all the messages, with each message having a time sent property and a username property for the user that sent the message. We scroll through the list of messages to find the flag!

### Flag

`osu{cH4TWUrst_m0RE_L1KE_wUrSt_ch47}`



Now that we know how to send requests to endpoints by looking at what key value pairs are being added to the dictionary (that will be turned into a JSON object to send as part of the POST request) in the decompiled code like we've been doing earlier, you can mess around and use the create message or group endpoints to send your own messages or create your own conversations without even having to use the app (by sending a JSON object inside of a POST request with the right fields to the right endpoint)! I sent a message to the group conversation that contained the flag using my credentials and the discovered group ID earlier (and creating a key-value pair `content` for the content of the message to send to the chat as specified by the JSON object that is created in the code--in the correct format as we assume the code should work properly and so the JSON object should be correctly formatted--that is then sent to the endpoint). That's crazy!!! 