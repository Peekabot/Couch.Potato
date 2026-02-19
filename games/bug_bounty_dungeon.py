#!/usr/bin/env python3
"""
Bug Bounty Dungeon - A Roguelike That Teaches Security

Win by FINDING BUGS in the game itself.

Traditional victory: Reach the treasure room
Real victory: Exploit the game's vulnerabilities

Intentional bugs:
1. Price manipulation - merchant trusts player gold value
2. IDOR - access any room by ID
3. Command injection - special parsing tricks
4. Save file tampering - no integrity checks
5. Integer overflow - strength can wrap negative

Source code is intentionally simple and readable.
This IS the lesson.

Usage:
    python3 bug_bounty_dungeon.py
"""

import json
import os
import sys


class Player:
    """Player character with exploitable attributes"""

    def __init__(self, name="Hero"):
        self.name = name
        self.room_id = 0  # Start in entrance
        self.gold = 100
        self.strength = 10
        self.level = 1
        self.inventory = []
        self.bugs_found = []

    def to_dict(self):
        """Serialize to JSON (no integrity check - BUG #4)"""
        return {
            'name': self.name,
            'room_id': self.room_id,
            'gold': self.gold,
            'strength': self.strength,
            'level': self.level,
            'inventory': self.inventory,
            'bugs_found': self.bugs_found
        }

    @staticmethod
    def from_dict(data):
        """Deserialize from JSON (trusts save file - BUG #4)"""
        p = Player(data['name'])
        p.room_id = data['room_id']
        p.gold = data['gold']
        p.strength = data['strength']
        p.level = data['level']
        p.inventory = data['inventory']
        p.bugs_found = data.get('bugs_found', [])
        return p


class Room:
    """Dungeon room"""

    def __init__(self, id, name, description, min_level=1):
        self.id = id
        self.name = name
        self.description = description
        self.min_level = min_level
        self.exits = {}  # direction -> room_id

    def add_exit(self, direction, room_id):
        self.exits[direction] = room_id


class Game:
    """Main game engine with intentional vulnerabilities"""

    SAVE_FILE = 'bug_bounty_dungeon_save.json'

    def __init__(self):
        self.player = None
        self.rooms = self.create_dungeon()
        self.turn = 0

    def create_dungeon(self):
        """Create the dungeon map"""
        rooms = {}

        # Room 0: Entrance
        r0 = Room(0, "Entrance Hall",
                  "A dimly lit entrance. Doors lead north and east.")
        r0.add_exit('north', 1)
        r0.add_exit('east', 2)
        rooms[0] = r0

        # Room 1: Shop
        r1 = Room(1, "Merchant's Shop",
                  "A merchant stands behind a counter. Type 'buy' to trade.")
        r1.add_exit('south', 0)
        rooms[1] = r1

        # Room 2: Guard Room
        r2 = Room(2, "Guard Room",
                  "A stern guard blocks the way north. (Requires level 5)",
                  min_level=5)
        r2.add_exit('west', 0)
        r2.add_exit('north', 3)
        rooms[2] = r2

        # Room 3: Treasure Vault (should be hard to reach)
        r3 = Room(3, "Treasure Vault",
                  "GOLD EVERYWHERE! You won by reaching here!",
                  min_level=10)
        r3.add_exit('south', 2)
        rooms[3] = r3

        # Room 99: Secret Admin Room (accessible via IDOR bug)
        r99 = Room(99, "Admin Vault",
                   "SECRET ROOM: You found the IDOR bug! This room has no normal entrance.",
                   min_level=1)
        rooms[99] = r99

        return rooms

    def current_room(self):
        """Get player's current room"""
        return self.rooms.get(self.player.room_id)

    def display_room(self):
        """Show current room"""
        room = self.current_room()
        print(f"\n{'='*60}")
        print(f"Room: {room.name}")
        print(f"{'='*60}")
        print(room.description)

        if room.exits:
            print(f"\nExits: {', '.join(room.exits.keys())}")

        print(f"\nPlayer: {self.player.name} | Level: {self.player.level} | "
              f"Gold: {self.player.gold} | Strength: {self.player.strength}")

        if self.player.bugs_found:
            print(f"Bugs found: {len(self.player.bugs_found)}")

    def move(self, direction):
        """Move to another room"""
        room = self.current_room()

        if direction not in room.exits:
            print(f"Can't go {direction} from here.")
            return

        next_room_id = room.exits[direction]
        next_room = self.rooms[next_room_id]

        # BUG #2: IDOR - Check level but don't verify room_id
        # Player can bypass by using 'goto' command
        if self.player.level < next_room.min_level:
            print(f"You need level {next_room.min_level} to enter. You are level {self.player.level}.")
            return

        self.player.room_id = next_room_id
        self.display_room()

        # Check victory
        self.check_victory()

    def goto(self, room_id_str):
        """
        Debug command for developers (should be removed before production)
        BUG #2: IDOR - No authorization check on room_id
        """
        try:
            room_id = int(room_id_str)

            if room_id not in self.rooms:
                print(f"Room {room_id} doesn't exist.")
                return

            # VULNERABILITY: No level check, no normal access control
            self.player.room_id = room_id

            # Track if bug was found
            if room_id == 99 and 'IDOR' not in self.player.bugs_found:
                self.player.bugs_found.append('IDOR')
                print("\n🐛 BUG FOUND: IDOR (Insecure Direct Object Reference)")
                print("You accessed a room without proper authorization!")

            self.display_room()
            self.check_victory()

        except ValueError:
            print("Invalid room ID")

    def buy(self):
        """
        Buy item from merchant
        BUG #1: Price manipulation - trusts player's gold value
        """
        room = self.current_room()

        if room.id != 1:
            print("No merchant here.")
            return

        print("\n--- Merchant's Inventory ---")
        print("1. Strength Potion - Increases strength by 50")
        print("2. Level Up Scroll - Increases level by 5")
        print(f"\nYour gold: {self.player.gold}")

        choice = input("What to buy? (1/2): ").strip()

        if choice == '1':
            price = 50
            item = "Strength Potion"
            effect = lambda: setattr(self.player, 'strength', self.player.strength + 50)
        elif choice == '2':
            price = 100
            item = "Level Up Scroll"
            effect = lambda: setattr(self.player, 'level', self.player.level + 5)
        else:
            print("Invalid choice")
            return

        # BUG #1: PRICE MANIPULATION
        # Server should verify price, but trusts player's gold value
        # If player edits save file to have negative gold, this breaks

        if self.player.gold >= price:
            self.player.gold -= price
            print(f"\nBought {item} for {price} gold!")
            effect()

            # Track bug if negative gold was used
            if self.player.gold < 0 and 'Price Manipulation' not in self.player.bugs_found:
                self.player.bugs_found.append('Price Manipulation')
                print("\n🐛 BUG FOUND: Price Manipulation")
                print("You bought something with insufficient funds!")
        else:
            print(f"Not enough gold. Need {price}, have {self.player.gold}.")

    def train(self):
        """
        Train to increase strength
        BUG #5: Integer overflow on strength
        """
        cost = 10

        if self.player.gold >= cost:
            self.player.gold -= cost
            self.player.strength += 100

            # BUG #5: No cap on strength, can overflow
            # If strength goes too high, it might wrap to negative
            if self.player.strength > 10000:
                self.player.strength = -1  # Simulate overflow

                if 'Integer Overflow' not in self.player.bugs_found:
                    self.player.bugs_found.append('Integer Overflow')
                    print("\n🐛 BUG FOUND: Integer Overflow")
                    print("Your strength overflowed to negative!")

            print(f"Trained! Strength is now {self.player.strength}")
        else:
            print(f"Need {cost} gold to train.")

    def execute_command(self, cmd):
        """
        Parse and execute command
        BUG #3: Command injection via special parsing
        """
        cmd = cmd.strip().lower()

        if not cmd:
            return

        # BUG #3: COMMAND INJECTION
        # Special syntax allows multiple commands
        # Example: "move north;goto 99" executes both

        if ';' in cmd:
            # Split on semicolon and execute each
            parts = cmd.split(';')

            if 'Command Injection' not in self.player.bugs_found and len(parts) > 1:
                self.player.bugs_found.append('Command Injection')
                print("\n🐛 BUG FOUND: Command Injection")
                print("You executed multiple commands at once!")

            for part in parts:
                self.execute_single_command(part.strip())
            return

        self.execute_single_command(cmd)

    def execute_single_command(self, cmd):
        """Execute a single parsed command"""

        parts = cmd.split()

        if not parts:
            return

        action = parts[0]

        # Movement
        if action in ['north', 'south', 'east', 'west', 'n', 's', 'e', 'w']:
            direction = {'n': 'north', 's': 'south', 'e': 'east', 'w': 'west'}.get(action, action)
            self.move(direction)

        # Look
        elif action in ['look', 'l']:
            self.display_room()

        # Inventory
        elif action in ['inventory', 'i']:
            print(f"\nInventory: {self.player.inventory or 'Empty'}")

        # Buy from merchant
        elif action == 'buy':
            self.buy()

        # Train
        elif action == 'train':
            self.train()

        # IDOR exploit (hidden debug command)
        elif action == 'goto' and len(parts) > 1:
            self.goto(parts[1])

        # Save
        elif action == 'save':
            self.save_game()

        # Load
        elif action == 'load':
            self.load_game()

        # Status
        elif action == 'status':
            print(f"\nName: {self.player.name}")
            print(f"Level: {self.player.level}")
            print(f"Gold: {self.player.gold}")
            print(f"Strength: {self.player.strength}")
            print(f"Room: {self.current_room().name}")
            print(f"Bugs found: {self.player.bugs_found}")

        # Help
        elif action == 'help':
            self.show_help()

        # Quit
        elif action in ['quit', 'q', 'exit']:
            print("\nThanks for playing!")
            sys.exit(0)

        else:
            print(f"Unknown command: {cmd}")
            print("Type 'help' for commands")

    def show_help(self):
        """Show available commands"""
        print("\n--- Commands ---")
        print("Movement: north, south, east, west (or n, s, e, w)")
        print("Actions: look, inventory, buy, train, status")
        print("System: save, load, help, quit")
        print("\nHidden commands exist... read the source code!")

    def save_game(self):
        """
        Save game to JSON
        BUG #4: No integrity check on save file
        """
        data = {
            'player': self.player.to_dict(),
            'turn': self.turn
        }

        with open(self.SAVE_FILE, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\nGame saved to {self.SAVE_FILE}")
        print("Hint: The save file is plain JSON... 🤔")

    def load_game(self):
        """
        Load game from JSON
        BUG #4: Trusts save file completely
        """
        if not os.path.exists(self.SAVE_FILE):
            print("No save file found")
            return

        with open(self.SAVE_FILE, 'r') as f:
            data = json.load(f)

        self.player = Player.from_dict(data['player'])
        self.turn = data['turn']

        # Track bug if save was tampered with
        # (e.g., player has level 99 or room_id 99 without playing)
        if (self.player.level > 20 or self.player.room_id == 99) and \
           'Save File Tampering' not in self.player.bugs_found:
            self.player.bugs_found.append('Save File Tampering')
            print("\n🐛 BUG FOUND: Save File Tampering")
            print("You modified the save file!")

        print("\nGame loaded")
        self.display_room()

    def check_victory(self):
        """Check for victory conditions"""

        # Traditional victory: Reach treasure vault
        if self.player.room_id == 3:
            print("\n" + "="*60)
            print("TRADITIONAL VICTORY!")
            print("="*60)
            print("You reached the Treasure Vault by playing normally.")
            print("But did you find the REAL victory condition?")
            print("="*60)

        # Real victory: Find bugs
        if len(self.player.bugs_found) >= 3:
            print("\n" + "="*60)
            print("🎉 TRUE VICTORY! 🎉")
            print("="*60)
            print("You won by BREAKING THE GAME!")
            print(f"\nBugs found ({len(self.player.bugs_found)}):")
            for i, bug in enumerate(self.player.bugs_found, 1):
                print(f"  {i}. {bug}")
            print("\nYou think like a security researcher.")
            print("This is how you find bugs in real APIs.")
            print("="*60)

            choice = input("\nContinue playing? (y/n): ").strip().lower()
            if choice != 'y':
                print("\nThanks for playing Bug Bounty Dungeon!")
                sys.exit(0)

    def start(self):
        """Start new game"""
        print("="*60)
        print("BUG BOUNTY DUNGEON")
        print("="*60)
        print("\nA roguelike that teaches security through play.")
        print("\nTwo ways to win:")
        print("  1. Traditional: Reach the treasure vault")
        print("  2. Real: Find and exploit 3+ bugs in the game")
        print("\nThe game has intentional vulnerabilities.")
        print("Your job: Find them.")
        print("\nHints:")
        print("  - The source code is simple and readable")
        print("  - Save files are JSON (inspectable)")
        print("  - Some commands are hidden")
        print("  - Think like a hacker")
        print("\nType 'help' for commands")
        print("="*60)

        name = input("\nEnter your name: ").strip() or "Hero"
        self.player = Player(name)

        self.display_room()
        self.game_loop()

    def game_loop(self):
        """Main game loop"""
        while True:
            try:
                cmd = input("\n> ").strip()
                self.execute_command(cmd)
                self.turn += 1

            except KeyboardInterrupt:
                print("\n\nGame interrupted")
                choice = input("Save before quitting? (y/n): ").strip().lower()
                if choice == 'y':
                    self.save_game()
                print("Goodbye!")
                sys.exit(0)

            except Exception as e:
                print(f"\nError: {e}")
                print("Type 'help' for commands")


def main():
    game = Game()

    # Check for existing save
    if os.path.exists(Game.SAVE_FILE):
        choice = input("Continue from save file? (y/n): ").strip().lower()
        if choice == 'y':
            game.player = Player()  # Initialize first
            game.load_game()
            game.game_loop()
            return

    game.start()


if __name__ == '__main__':
    main()
