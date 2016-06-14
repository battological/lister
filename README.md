Lister
======

Falcon API for a simple list making app.

# API

## GET

### User info
> /user/{userId}

Return information about user, if public, including basic information about their lists:
```
{
  "user": id,
  "name": name,
  "lists": [
    { "id": listID, "title": title, "description": description },
    ...
  ]
}
```

---

### User lists
> /user/{userId}/lists

Return a list of the IDs of `user`'s lists:
```
["listID1", ...]
```

---

### List
> /list/{listId}

Return the list with specified ID:
```
{
  "title": listTitle,
  "description": listDescription,
  [
    { "item": itemID, "title": itemTitle, "description": itemDescription },
    ...
  ]
}
```

## POST

### Create list
> /list/new

Create a new list. You must name the list in a JSON object in the request body, and optionally add a description, like so:
```
{ "title": "My New List", "description": "My list's description" }
```

Returns the ID of the newly created list:
```
{ "id": listId }
```

### Add item to list
> /list/{listId}/add

Add an item to the list. The item must be passed as a JSON object in the request body. List items must have a title field and accept an optional description field. For example:
```
{ "title": "Item1" } // valid

{ "title": "Item1", "description": "This is a valid list item." }

{ "description": "This is *not* a valid list item." }

{
  "title": "Item1",
  "description": "The API will ignore the 'color' field, but accept the 'title' and 'description' fields.",
  "color": "red"
}
```
Returns the ID of the newly created item:
```
{ "id": itemId }
```

## PUT

### Edit list name
> /list/{listId}

You must supply either a new title or new description for the specified list:
```
{ "title": "My New List Title" }

{ "description": "My new list description" }

{ "title": "My New List Title", "description": "My new list description" }
```

Returns only the appropriate HTTP response, e.g. 200, 403, etc.

### Edit list item
> /list/{listId}/{itemId}

You must supply a JSON object with any fields you wish to edit, e.g.:
```
{ "title": "New Title", "description": "New description." }

{ "title": "New Title" }
```

Returns only the appropriate HTTP response.

## DELETE

### Delete list
> /list/{listId}

### Delete list item
> /list/{listId}/{itemId}
