import os
from pyvis.network import Network

class VisualThreatGraph:
    def __init__(self, apk_name):
        self.apk_name = apk_name
        # Dark theme for real hacker/SOC vibes
        self.net = Network(height='800px', width='100%', bgcolor='#121212', font_color='white', directed=True)
        
        # Add the Central Node (The APK itself)
        self.net.add_node(
            self.apk_name, 
            label=f"⚠️ {self.apk_name}", 
            color='#FF3B30', # Red for APK
            shape='hexagon', 
            size=40,
            title="Target APK"
        )

    def add_entities(self, category, items, node_color, node_shape, icon_prefix=""):
        """Helper function to add nodes and connect them to the APK"""
        if not items:
            return
            
        for item in items:
            # Clean up long strings for display
            display_item = str(item)
            if len(display_item) > 30:
                display_item = display_item[:27] + "..."
                
            node_id = f"{category}_{item}"
            # Add Node
            self.net.add_node(
                node_id, 
                label=f"{icon_prefix} {display_item}", 
                color=node_color, 
                shape=node_shape, 
                title=f"{category}: {item}",
                size=20
            )
            # Add Edge (Line connecting APK to this node)
            self.net.add_edge(self.apk_name, node_id, color="#555555")

    def generate_report(self, permissions, urls, secrets, output_filename="threat_graph.html"):
        """Generates the final interactive HTML graph"""
        print("[*] Generating Visual Threat Graph...")
        
        # 1. Add Permissions (Orange Triangles)
        self.add_entities("Permission", permissions, node_color='#FF9500', node_shape='triangle', icon_prefix="🔑")
        
        # 2. Add URLs/Domains (Blue Diamonds)
        self.add_entities("URL", urls, node_color='#007AFF', node_shape='diamond', icon_prefix="🌐")
        
        # 3. Add Hardcoded Secrets (Green Dots)
        all_secrets = []
        if isinstance(secrets, dict):
            for sec_type, vals in secrets.items():
                for v in vals:
                    all_secrets.append(f"{sec_type}: {v}")
        self.add_entities("Secret", all_secrets, node_color='#34C759', node_shape='dot', icon_prefix="🛡️")

        # Add physics for that cool floating animation
        self.net.barnes_hut(gravity=-8000, central_gravity=0.3, spring_length=150)
        
        # Save and output
        self.net.write_html(output_filename)
        print(f"[+] BOOM! Graph saved to {output_filename}. Open it in your browser!")
        return output_filename
