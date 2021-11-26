# FridgeMate Expiry Tracker

This is capstone project for Havard's CS50 course. I'm fairly new to programming so my code isn't up to any standards other then my own
The spark for the idea came from a realization that I'm really bad at remembering when items in my fridge are going to expire, so I decided to develop this tracker. 
At the moment it has some basic functionality:
- User registration which includes confirmation email (sends token linked to desired username)
- User profiles, login and logout functionality with a forgot password button link on the login screen.
- Forgot password link will generate a token and send it in an email to the users specified email, only valid tokens will generate a change password screen.
- Main fridge view where a user can see all items currently in fridge and days remaining until expiry.
- Users can delete old expired items / mistakes right from the fridge view page
- Fridge view links to an add item page where users can choose to add a new item (relative to users history), or add a previously used item
- From the users profile page they will be able to see their information, change their password and update their information (name, username, email) as well as set their notification preferences