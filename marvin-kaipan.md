# marvin

## by *kaipan*

### Description

We must exploit an old version of the OSUSEC discord bot named Marvin. We are given the source code for the old Marvin bot on GitHub and we must join a discord server to access the old Marvin bot for running commands using the bot. We are given the hint that an exploitable bug was discovered by a user with a single quote in their name. The single quote leads us to believe that the quote could serve as a possible escape character that allows for some sort of arbitrary command injection or manipulation of the bot's behavior. Since this is a bot that is tied to the club, we surmise that the bot interacts with some sort of backend or database, so it is likely that the single quote is an escape character for a possible SQL injection exploit where SQL is a common database manipulation/querying language. Upon looking at the source code files, we see that the Python code files use SQL functions, and there is also a *ctf_league.sql* file that contains all of the commands that create the database tables using SQL, so we can confirm that we most likely have to perform a SQL injection where we can run an arbitrary query of our choosing to manipulate the database to give us the flag.

### Finding The Exploitable Query

Now that we know that we need to perform a SQL injection, we need to find the section of the code that allows for a SQL injection. The only file that contains anything useful for SQL injection is the *Member.py* file. SQL injection is all about running our own query, so we need to find code that runs a SQL query based on our own input so we can build our own query that returns the flag. We also need to make sure that the code returns the results from the query to the user; if we can query the database for the flag but the bot doesn't return the result then getting the flag from the database doesn't matter because we can't see or use the flag. Using these two criteria, we narrow down suitable bot commands that we can use to perform a SQL injection in the *Member.py* file (this .py file contains all the code for the user commands that you can get the bot to run on Discord). Some commands like `$submit` allow you to enter your own input and build the SQL query to your liking, but don't return the results of your query and instead return string literals, so we can't see the flag even if we got it. Others like `$solves` don't let you enter your own input at all so you can't build your own exploit query to get the flag to begin with.

The perfect function we found was `$info` since you can enter the name of the challenge on your own, which lets you build a payload in the place of the challenge name to get the information of. It also returns the information from the database so that the bot can print the results (including the flag) to us on Discord.

### SQL Injection

The line of code that does the SQL query for the `$info` command and stores the result of the query is:

```python
chal_details = self.db.sql_fetchone("SELECT name,category,points,download,access,description FROM challenges WHERE name='%s'" % name)
```

We can't change the already existing query, so we need to find a way to attach our own arbitrary query that gets the flag onto this existing query and also make it execute as well. We can see here that our user input, the challenge name we wish to get information for stored in variable `name`, is substituted at the end of the query for the placeholder `%s` to create the final query to send to the database. So we need to create our SQL payload that we put in the `name` variable such that when this payload replaces `%s` we get a working query that gets us the flag. We choose to use the `UNION` SQL operator for our payload SQL query so that the results of our query will be combined with the results of the hardcoded query that we are unable to change. Once our rsults that contain the flag get combined the with the intended original query it returns the combined result and Marvin will print out the combined result with the flag in it. The `UNION` operator requires that we query the same number of columns with similar data types and also query the same column order. The hardcoded query has six columns that are returned, and it lists the columns in order from left to right, so our payload needs to have these same columns queried except we replace one column to the flag column, so that the database returns the flag to the bot to print out.

The final SQL payload that we use is `" marvin' UNION SELECT name,category,flag,download,access,description FROM challenges WHERE name='marvin"` which we can see matches the constraints described earlier for using `UNION`; we choose the same number of columns (six) and replace the points column with the flag column to get the flag in our combined result. We also use the `WHERE` clause and set the condition to `name='marvin"` because we only care about the result where the challenge is named marvin, which is the current challenge, so that all the column values, including the flag column, have to belong to the current challenge. It filters out the query results so that the flag value we get belongs to the current challenge that we are trying to solve. We also need to be mindful of the quotations that we include in our payload. We surround the entire payload in double quotes because the hint states that

> Bot commands in discord.py allow you to pass a string with spaces as an argument to a command when you surround the argument with double quotes.

Since our payload will be passed to the database as an argument to the `name` variable through a bot command and our payload contains spaces, we have to surround the argument/payload with double quotes. We also should note the single quote the two scattered single quotes in the payload. The single quote after `" marvin' <--`

Is for closing out/escaping the single quote in the hardcoded query at the `name= -->'%s` spot. Once we close out the opening single quote before `%s`. We can attach another query, which is our `UNION SELECT...` query stated earlier. The single quote at the end of the payload (`name= -->'marvin"`) is for closing out the closing single quote in the original hardcoded query (`name='%s' <--`) since that single quote was supposed to close out the `%s`, but with us closing it in our payload after `marvin` and before `UNION SELECT...` this ending closing single quote in the original query becomes "dangling" and so we untangle it once again at the end of our payload by providing an opening single quote in our payload. If we accounted for the quotes properly, then the final payload should look like this after the `%s` placeholder gets replaced by our payload:

```sql
"SELECT name,category,points,download,access,description FROM challenges WHERE name=' marvin' UNION SELECT name,category,flag,download,access,description FROM challenges WHERE name='marvin'"
```

We can see that all quotes are balanced and closed off properly with no dangling quotes after we account for them in our payload, and our modified query is a valid query that the databse can execute without giving us an annoying syntax error.

### Command

Since we need to pass the payload to the bot using a bot command, the command that we use with the payload taking the place of the challenge name that we would specify if we were using the `$info` command as intended is shown below:

`$info " marvin' UNION SELECT name,category,flag,download,access,description FROM challenges WHERE name='marvin"`

Running this command on the old Marvin bot will return the combined results containing the challenge information stored in the database, but since we replaced the point column with the flag column in our payload query, the information for the *POINTS* label is actually the flag.

> NAME: marvin
>
> CATEGORY: rev 
>
> POINTS: osu{GOoD_lUCK_F1Nd1nG_7H15_M4rv1N_wOuLd_neVer_lE4k_4_fl4g} 
>
> DOWNLOAD LINK: https://github.com/BobbySinclusto/marvin 
>
> ACCESS: https://discord.gg/nvezFTxNJy 
>
> DESCRIPTION: On October first, 2021, during the first ctf-league meeting of the 2021-2022 school year, the ultra stable and super secure marvin was hacked (unintentionally) by one of our very own ctf-league players who had a single quote in their username. Luckily, no sensitive data was exposed and the bug(s) were fixed the same night that they were discovered. Tonight we're taking a step back in time, to find out how much damage the vulnerabilities could have caused if they had been left unchecked. The flag for tonight's challenge has been added to old_marvin's database. Good luck!

### Flag

`osu{GOoD_lUCK_F1Nd1nG_7H15_M4rv1N_wOuLd_neVer_lE4k_4_fl4g}`