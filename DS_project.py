#!/usr/bin/env python
# coding: utf-8

# In[36]:


"""
    the hashing function 
    name = sha_256
    how to use it:
        sha_256(string_name)
    example:
        sha_256("iust") == 'f80c97914c79caaa9589d3711bc209bea4b3f14c17ae45454c528d0183e8a30a'
    
    from: https://stackoverflow.com/
    
"""

initial_hash_values=[
'6a09e667','bb67ae85','3c6ef372','a54ff53a',
'510e527f','9b05688c','1f83d9ab','5be0cd19'
]

sha_256_constants=[
'428a2f98','71374491','b5c0fbcf','e9b5dba5',
'3956c25b','59f111f1','923f82a4','ab1c5ed5',
'd807aa98','12835b01','243185be','550c7dc3',
'72be5d74','80deb1fe','9bdc06a7','c19bf174',
'e49b69c1','efbe4786','0fc19dc6','240ca1cc',
'2de92c6f','4a7484aa','5cb0a9dc','76f988da',
'983e5152','a831c66d','b00327c8','bf597fc7',
'c6e00bf3','d5a79147','06ca6351','14292967',
'27b70a85','2e1b2138','4d2c6dfc','53380d13',
'650a7354','766a0abb','81c2c92e','92722c85',
'a2bfe8a1','a81a664b','c24b8b70','c76c51a3',
'd192e819','d6990624','f40e3585','106aa070',
'19a4c116','1e376c08','2748774c','34b0bcb5',
'391c0cb3','4ed8aa4a','5b9cca4f','682e6ff3',
'748f82ee','78a5636f','84c87814','8cc70208',
'90befffa','a4506ceb','bef9a3f7','c67178f2'
]

def bin_return(dec):
    return(str(format(dec,'b')))

def bin_8bit(dec):
    return(str(format(dec,'08b')))

def bin_32bit(dec):
    return(str(format(dec,'032b')))

def bin_64bit(dec):
    return(str(format(dec,'064b')))

def hex_return(dec):
    return(str(format(dec,'x')))

def dec_return_bin(bin_string):
    return(int(bin_string,2))

def dec_return_hex(hex_string):
    return(int(hex_string,16))

def L_P(SET,n):
    to_return=[]
    j=0
    k=n
    while k<len(SET)+1:
        to_return.append(SET[j:k])
        j=k
        k+=n 
    return(to_return)

def s_l(bit_string):
    bit_list=[]
    for i in range(len(bit_string)):
        bit_list.append(bit_string[i])
    return(bit_list)

def l_s(bit_list):
    bit_string=''
    for i in range(len(bit_list)):
        bit_string+=bit_list[i]
    return(bit_string)

def rotate_right(bit_string,n):
    bit_list = s_l(bit_string)
    count=0
    while count <= n-1:
        list_main=list(bit_list)
        var_0=list_main.pop(-1)
        list_main=list([var_0]+list_main)
        bit_list=list(list_main)
        count+=1
    return(l_s(list_main))

def shift_right(bit_string,n):
    bit_list=s_l(bit_string)
    count=0
    while count <= n-1:
        bit_list.pop(-1)
        count+=1
    front_append=['0']*n
    return(l_s(front_append+bit_list))

def mod_32_addition(input_set):
    value=0
    for i in range(len(input_set)):
        value+=input_set[i]
    mod_32 = 4294967296
    return(value%mod_32)

def xor_2str(bit_string_1,bit_string_2):
    xor_list=[]
    for i in range(len(bit_string_1)):
        if bit_string_1[i]=='0' and bit_string_2[i]=='0':
            xor_list.append('0')
        if bit_string_1[i]=='1' and bit_string_2[i]=='1':
            xor_list.append('0')
        if bit_string_1[i]=='0' and bit_string_2[i]=='1':
            xor_list.append('1')
        if bit_string_1[i]=='1' and bit_string_2[i]=='0':
            xor_list.append('1')
    return(l_s(xor_list))

def and_2str(bit_string_1,bit_string_2):
    and_list=[]
    for i in range(len(bit_string_1)):
        if bit_string_1[i]=='1' and bit_string_2[i]=='1':
            and_list.append('1')
        else:
            and_list.append('0')
            
    return(l_s(and_list))

def or_2str(bit_string_1,bit_string_2):
    or_list=[]
    for i in range(len(bit_string_1)):
        if bit_string_1[i]=='0' and bit_string_2[i]=='0':
            or_list.append('0')
        else:
            or_list.append('1')
    return(l_s(or_list))

def not_str(bit_string):
    not_list=[]
    for i in range(len(bit_string)):
        if bit_string[i]=='0':
            not_list.append('1')
        else:
            not_list.append('0')
    return(l_s(not_list))

'''
SHA-256 Specific Functions:
'''

def Ch(x,y,z):
    return(xor_2str(and_2str(x,y),and_2str(not_str(x),z)))

def Maj(x,y,z):
    return(xor_2str(xor_2str(and_2str(x,y),and_2str(x,z)),and_2str(y,z)))

def e_0(x):
    return(xor_2str(xor_2str(rotate_right(x,2),rotate_right(x,13)),rotate_right(x,22)))

def e_1(x):
    return(xor_2str(xor_2str(rotate_right(x,6),rotate_right(x,11)),rotate_right(x,25)))

def s_0(x):
    return(xor_2str(xor_2str(rotate_right(x,7),rotate_right(x,18)),shift_right(x,3)))

def s_1(x):
    return(xor_2str(xor_2str(rotate_right(x,17),rotate_right(x,19)),shift_right(x,10)))

def message_pad(bit_list):
    pad_one = bit_list + '1'
    pad_len = len(pad_one)
    k=0
    while ((pad_len+k)-448)%512 != 0:
        k+=1
    back_append_0 = '0'*k
    back_append_1 = bin_64bit(len(bit_list))
    return(pad_one+back_append_0+back_append_1)
    
def message_bit_return(string_input):
    bit_list=[]
    for i in range(len(string_input)):
        bit_list.append(bin_8bit(ord(string_input[i])))
    return(l_s(bit_list))

def message_pre_pro(input_string):
    bit_main = message_bit_return(input_string)
    return(message_pad(bit_main))

def message_parsing(input_string):
    return(L_P(message_pre_pro(input_string),32))

def message_schedule(index,w_t):
    new_word = bin_32bit(mod_32_addition([int(s_1(w_t[index-2]),2),int(w_t[index-7],2),int(s_0(w_t[index-15]),2),int(w_t[index-16],2)]))
    return(new_word)

'''
This example of SHA_256 works for an input string <56 characters.
'''

def sha_256(input_string):
    assert len(input_string) < 56, "This example of SHA_256 works for an input string <56 characters."
    w_t=message_parsing(input_string)
    a=bin_32bit(dec_return_hex(initial_hash_values[0]))
    b=bin_32bit(dec_return_hex(initial_hash_values[1]))
    c=bin_32bit(dec_return_hex(initial_hash_values[2]))
    d=bin_32bit(dec_return_hex(initial_hash_values[3]))
    e=bin_32bit(dec_return_hex(initial_hash_values[4]))
    f=bin_32bit(dec_return_hex(initial_hash_values[5]))
    g=bin_32bit(dec_return_hex(initial_hash_values[6]))
    h=bin_32bit(dec_return_hex(initial_hash_values[7]))
    for i in range(0,64):
        if i <= 15: 
            t_1=mod_32_addition([int(h,2),int(e_1(e),2),int(Ch(e,f,g),2),int(sha_256_constants[i],16),int(w_t[i],2)])
            t_2=mod_32_addition([int(e_0(a),2),int(Maj(a,b,c),2)])
            h=g
            g=f
            f=e
            e=mod_32_addition([int(d,2),t_1])
            d=c
            c=b
            b=a 
            a=mod_32_addition([t_1,t_2])
            a=bin_32bit(a)
            e=bin_32bit(e)
        if i > 15:
            w_t.append(message_schedule(i,w_t))
            t_1=mod_32_addition([int(h,2),int(e_1(e),2),int(Ch(e,f,g),2),int(sha_256_constants[i],16),int(w_t[i],2)])
            t_2=mod_32_addition([int(e_0(a),2),int(Maj(a,b,c),2)])
            h=g
            g=f
            f=e
            e=mod_32_addition([int(d,2),t_1])
            d=c
            c=b
            b=a 
            a=mod_32_addition([t_1,t_2])
            a=bin_32bit(a)
            e=bin_32bit(e)
    hash_0 = mod_32_addition([dec_return_hex(initial_hash_values[0]),int(a,2)])
    hash_1 = mod_32_addition([dec_return_hex(initial_hash_values[1]),int(b,2)])
    hash_2 = mod_32_addition([dec_return_hex(initial_hash_values[2]),int(c,2)])
    hash_3 = mod_32_addition([dec_return_hex(initial_hash_values[3]),int(d,2)])
    hash_4 = mod_32_addition([dec_return_hex(initial_hash_values[4]),int(e,2)])
    hash_5 = mod_32_addition([dec_return_hex(initial_hash_values[5]),int(f,2)])
    hash_6 = mod_32_addition([dec_return_hex(initial_hash_values[6]),int(g,2)])
    hash_7 = mod_32_addition([dec_return_hex(initial_hash_values[7]),int(h,2)])
    final_hash =''.join ([hex_return(hash_0), # changes = ''.join ([])
                  hex_return(hash_1),
                  hex_return(hash_2),
                  hex_return(hash_3),
                  hex_return(hash_4),
                  hex_return(hash_5),
                  hex_return(hash_6),
                  hex_return(hash_7)])
    return(final_hash)


# In[37]:


#import the libraries

from collections import deque
import plotly.graph_objs as go




# In[38]:


class Family: #create the class
    
    def __init__(self, person): #person is the name of that person 
        self.name = person
        self.father = None    #this tree fills with the function 
        self.mother = None    
        self.children = []
        
    def add_father(self, father): # add the father of the node 
        self.father = father

    def add_mother(self, mother): # add the mother of the node 
        
        self.mother = mother

    def add_child(self, child):        # add the childrene of the node that can be more than one
        self.children.append(child)    # but the parents are uniqe
        
        
    def find(self, person_name): # for the input argument we should give the root 
        # Recursively find a person in the family tree
        if self.name == person_name:
            return self
        for child in self.children:
            result = child.find(person_name)
            if result:
                return result
        return None
         #------------------------------------------------O(n)-----------------------------------------------------------------


    def delete(self):        # problem
        self.name = "dead"
        return "Done"
        #------------------------------------------------O(1)-----------------------------------------------------------------


    def size(self):  
        # Calculate the size of the family tree (number of nodes)
        count = 1  # counting the current node
        for child in self.children:
            count += child.size()
            child.size()
        return count
        #------------------------------------------------O(n)-----------------------------------------------------------------

#-----------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
    def is_child(self, person_name): # چک کردن والد و فرزند بودن
        for child in self.children:  #
            if child.name == person_name.name:
                return True
            elif child.is_child(person_name):  # Recursive call should check the return value
                return True                    # in the elif  checks that thats its find ora not 
        return False
                        
                        
    def is_siblings(self, other): #چک کردن برادر یا خواهر بودن
        if self.father == other.father and self.mother == other.mother: # simple :)
            return True
        else:
            return False
     
        
    def farest(self):# پیدا کردن  فاصله دورترین زاده
        '''
                in fact we want to find the hieght of the node 
                we search in children of the node and return the max
                if the node dosent have any child return 0
                Example usage:
                Let's build a simple tree
                                A
                               / \
                              B   C
                             /   / \
                            D   E   F
                farest(nodeB))  -> Output should be 1
        '''
     #------------------------------------------------O(n)-----------------------------------------------------------------

        if not self.children:
            return 0

        else:
            return 1 + max(child.farest() for child in self.children) 
    
    
    def max_width_and_values(root): # پیدا کردن فاصله دورترین رابطه خیشاوندی
        
    
        #------------------------------------------------O(V+E)-----------------------------------------------------------------
        #where V is number of vertices and E is number of edges in Family tree
        if not root:
            return 0, []

        max_width = 0
        max_width_level_values = []
        queue = deque([(root, 0)])

        current_level = 0
        current_level_values = []
        current_level_width = 0

        while queue:
            node, level = queue.popleft()

            if level == current_level:
                current_level_values.append(node.name)
                current_level_width += 1
            else:
                if current_level_width > max_width:
                    max_width = current_level_width
                    max_width_level_values = current_level_values

                current_level_values = [node.name] # name -> value
                current_level_width = 1
                current_level = level

            for child in node.children:
                queue.append((child, level + 1))

        if current_level_width > max_width:
            max_width = current_level_width
            max_width_level_values = current_level_values

        return max_width, max_width_level_values
    
    
    
    
    def far_relation(self, other):  # پیدا کردن جد مشترک
        dis = 1
        if self.name == other.name:
            return self.name
        else:
            return self.father.far_relation(other.father)
        #------------------------------------------------O(n)-----------------------------------------------------------------



    
    
    
    def is_related(self, other): #چک کردن رابطه فامیلی دور
        """
        This function checks if self and other are part of the same family tree (i.e., related)
        by looking for any common ancestor.
        """
        #------------------------------------------------O(n**2)-----------------------------------------------------------------

        # Internal recursive function to find all ancestors of a Family node
        def find_ancestors(person): #  چک کردن رابطه فامیلی دور
            ancestors = set() # in this code we check for both mother and father but its un neccery to check the mother 
                              # this Family Tree is fathers based
            if person is None:
                return ancestors
            # Add the current person to the set of ancestors
            ancestors.add(person)
            # Recursively find and add all ancestors from the father's side
            ancestors.update(find_ancestors(person.father))
            # Recursively find and add all ancestors from the mother's side
            ancestors.update(find_ancestors(person.mother))
            return ancestors
    
        # Find all ancestors for both self and other
        self_ancestors = find_ancestors(self)
        other_ancestors = find_ancestors(other)
        
        # Determine if there's a common ancestor:
        # If the intersection is not empty, then they are related.
        return len(self_ancestors.intersection(other_ancestors)) > 0   
    
#---------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------
 
    def visualize_family_tree(root):
        # This will be recursively called to fill in the node and edge information
        def traverse(member, depth):
            if member.name in positions:
                return # Already visited this member
            positions[member.name] = (depth, len(levels[depth]))  # Use depth for x, order for y position
            levels[depth].append(member.name)
            if member.father:
                traverse(member.father, depth+1)
                edges.append((member.father.name, member.name))
            if member.mother:
                traverse(member.mother, depth+1)
                edges.append((member.mother.name, member.name))
            for child in member.children:
                traverse(child, depth-1)
                edges.append((member.name, child.name))

        positions = {}  # To hold the (x,y) positions of each member
        edges = []      # To hold the tuples representing family connections
        levels = {}     # Each depth level in the family tree

        # Initialize levels with empty lists for each potential depth
        for i in range(-10, 11): # Assuming the tree won't be deeper than 20 generations either way
            levels[i] = []

        # Start the recursive process from the 'root' of the family tree
        # Generally the youngest member without children is used as the root
        traverse(root, 0)

        # Generate node and edge information suitable for plotting with Plotly
        node_x = []
        node_y = []
        node_text = []
        edge_x = []
        edge_y = []

        for name, (depth, order) in positions.items():
            node_x.append(depth)
            node_y.append(order)
            node_text.append(name)

            for parent, child in edges:
                if parent == name or child == name:
                    parent_pos = positions[parent]
                    child_pos = positions[child]
                    edge_x.extend([parent_pos[0], child_pos[0], None])
                    edge_y.extend([parent_pos[1], child_pos[1], None])

        # Plot the nodes
        node_trace = go.Scatter(x=node_x, y=node_y, text=node_text, mode='markers+text', textposition='bottom center')

        # Plot the edges
        edge_trace = go.Scatter(x=edge_x, y=edge_y, mode='lines')

        # Create a Plotly figure
        fig = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(title='Family Tree',
                                         showlegend=False,
                                         hovermode='closest'))

        # Display the figure
        fig.show()

    # Usage:
    # root = Family("YoungestMemberName")
    # set up the family tree with add_father, add_mother, add_child
    # visualize_family_tree(root)

        
    


# # menue 
# 
# 
# ### def is_child(other)
# 
# ### def is_siblings(other)
# 
# ### def max_width_and_values()
# 
# ### def farest()
# 
# ### def is_related(other)
# 
# ### def far_relation(other)
# 
# ### def root.visualize_family_tree()
# 
# 
#                                 A
#                                / \
#                               B   C
#                              /   / \
#                             D   E   F
# 
# 
# 
# 

# In[43]:


a = Family('A')
b = Family('B')
c = Family('C')
d = Family('D')
e = Family('E')
f = Family('F')

# Set up the> relationships
a.add_child(b)
a.add_child(c)
b.add_child(d)
c.add_child(e)
c.add_child(f)

# Assuming we are giving a father or mother attribute but we'll go with father for simplicity
b.add_father(a)
c.add_father(a)
d.add_father(b)
e.add_father(c)
f.add_father(c)
 
print(a.size()) # done
# print(b.delete()) # done 
print(f.far_relation(d)) # done
print(a.is_child(c)) #done
print(e.is_siblings(f)) # done 
print(a.max_width_and_values()) # done
print(a.farest()) #done
print(b.is_related(c)) # done 
print(a.visualize_family_tree())


# In[39]:


a = Family(sha_256('A'))
b = Family(sha_256('B'))
c = Family(sha_256('C'))
d = Family(sha_256('D'))
e = Family(sha_256('E'))
f = Family(sha_256('F'))

# Set up the> relationships
a.add_child(b)
a.add_child(c)
b.add_child(d)
c.add_child(e)
c.add_child(f)

# Assuming we are giving a father or mother attribute but we'll go with father for simplicity
b.add_father(a)
c.add_father(a)
d.add_father(b)
e.add_father(c)
f.add_father(c)
print(e.far_relation(f)) # done 
print(a.size()) # done
# print(b.delete()) # done 
print(a.is_child(c)) #done
print(e.is_siblings(f)) # done 
print(a.max_width_and_values()) # done
print(a.farest()) #done
print(b.is_related(c)) # done 
print(a.visualize_family_tree())

