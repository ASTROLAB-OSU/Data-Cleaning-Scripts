import json
import matplotlib.pyplot as plt
import numpy as np

def visualize_occurrence_relationships(json_file):
    """
    Create scatter plots comparing standalone vs followup occurrences for prefixes
    using logarithmic scales.
    
    Args:
        json_file (str): Path to JSON file containing all stats
    """
    # Load JSON data
    with open(json_file, 'r') as f:
        all_stats = json.load(f)

    # Create figure
    plt.figure(figsize=(15, 10))

    # Colors and markers for different datasets
    colors = ['b', 'g', 'r', 'c', 'm', 'y', 'k']
    markers = ['o', 's', '^', 'v', 'D', 'p', '*']

    # Process each dataset
    for idx, (dataset_name, stats) in enumerate(all_stats.items()):
        # Extract data
        standalone = [stat['standalone_count'] for stat in stats]
        followup = [stat['following_count'] for stat in stats]
        prefixes = [stat['prefix'] for stat in stats]

        # Compute ratios (handling cases where followup is zero)
        ratios = []
        for stand, foll in zip(standalone, followup):
            if foll == 0:
                # Use a small value instead of infinity for log scale
                ratios.append(stand)
            else:
                ratios.append(stand / foll)

        # Create scatter plot
        color_idx = idx % len(colors)
        marker_idx = idx % len(markers)
        plt.scatter(standalone, followup,
                   c=colors[color_idx],
                   marker=markers[marker_idx],
                   label=dataset_name,
                   alpha=0.6)

        # Add annotations for notable points
        for i, prefix in enumerate(prefixes):
            # Adjust threshold for annotation in log space
            if (np.log10(standalone[i]) > np.log10(max(standalone)) - 1 or
                np.log10(followup[i]) > np.log10(max(followup)) - 1):
                plt.annotate(prefix,
                            (standalone[i], followup[i]),
                            xytext=(5, 5),
                            textcoords='offset points',
                            fontsize=8)

    # Customize plot with log scales
    # plt.xscale('log')
    # plt.yscale('log')
    plt.xlabel('Standalone Occurrences (log scale)')
    plt.ylabel('Followup Occurances (log scale)')
    plt.title('Prefix Usage Analysis: Standalone vs Followup Occurrences')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, alpha=0.3, which='both')  # Add grid lines for both major and minor ticks

    # Set reasonable limits for log scales
    plt.xlim(left=0, right=1000000)  # Start at 1 since log(0) is undefined
    plt.ylim(bottom=0, top=1000000)  # Allow ratios below 1

    # Add some padding
    plt.margins(0.1)

    # Adjust layout
    plt.tight_layout()

    # Save plot
    output_path = 'for_graph.png'
    plt.savefig(output_path, bbox_inches='tight', dpi=300)
    plt.close()
    
    print(f"Plot saved as: {output_path}")

# Example usage
if __name__ == "__main__":
    json_file = "./data_cleaning/prefix_statistics.json"
    visualize_occurrence_relationships(json_file)