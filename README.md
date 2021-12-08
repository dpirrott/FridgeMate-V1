# FridgeMate Expiry Tracker
### Video demo: <URL HERE>
### Description:
The motivation for this project came from a realization that I personally find it difficult to keep track of all the expiry dates for products in my fridge. FridgeMate is a solution to keeping track of any number of expriy dates for products in your fridge. Originally FridgeMate was going to be an iOS app, but upon realizing that swift was restricted to Mac OS, I decided to go with a web application with mobile responsiveness in mind. Originally the notification system was going to be through push notifications on iOS, but after switching to a web application, emails alerts seemed like the best option. 

#### User registration and login:






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
