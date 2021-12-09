# FridgeMate Expiry Tracker
### Video demo: <URL HERE>
### Description:

The motivation for this project came from a realization that I personally find it difficult to keep track of all the expiry dates for products in my fridge. FridgeMate is a solution to keeping track of any number of expriy dates for products in your fridge. Originally FridgeMate was going to be an iOS app, but upon realizing that swift was restricted to Mac OS, I decided to go with a web application with mobile responsiveness in mind. Originally the notification system was going to be through push notifications on iOS, but after switching to a web application, emails alerts seemed like the best option. 

**The following sections will describe every aspect of FridgeMate from both a users standpoint and alittle description of what's happening in the background.**

#### Welcome/landing page:
The purpose of the welcome page is to give a brief preview of FridgeMate and allow new users to sign-up. The welcome page was not my primary concern for the app but it was added because the sign-in page didn't express what the app actually does.

The welcome page allowed me to learn how to use the following CSS/Boostrap features:
- Adding a background image to a container
- Use of opacity to make text clear in the overlays
- Learned how to use a timed Bootstrap carousel with information slides on FridgeMate
- Use of ```display: grid;``` to format the slides

#### User registration and login:
Users can get to the registration page via the menu at the top of the screen or the register button on the login page.

Users will be required to enter the following information when registering:
- Name
- Email ***(must be unique)***
- Username ***(5 character minimum and unique)***
- Password ***(5 character minimum and must match password confirmation field)***
- Confirm password ***(must match password field)***

Javascript was used on the registration page to prevent a user from being able to submit the form unless the conditions above are all met. The submit button remains disabled via "```$(#submitBtn).prop("disabled", true)```" until the form data is accepted. Since a user can just go into the browsers developer tools and remove the disabled attribute, a backend safeguard was also applied to verify the same conditions.

At the moment it has some basic functionality:
- User registration which includes confirmation email (sends token linked to desired username)
- User profiles, login and logout functionality with a forgot password button link on the login screen.
- Forgot password link will generate a token and send it in an email to the users specified email, only valid tokens will generate a change password screen.
- Main fridge view where a user can see all items currently in fridge and days remaining until expiry.
- Users can delete old expired items / mistakes right from the fridge view page
- Fridge view links to an add item page where users can choose to add a new item (relative to users history), or add a previously used item
- From the users profile page they will be able to see their information, change their password and update their information (name, username, email) as well as set their notification preferences
