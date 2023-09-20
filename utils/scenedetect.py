from scenedetect import SceneManager, open_video, ContentDetector
# for testing
def find_scenes(video_path, threshold=27.0):
    video = open_video(video_path)
    scene_manager = SceneManager()
    scene_manager.add_detector(
        ContentDetector(threshold=threshold))

    scene_manager.detect_scenes(video)

    return scene_manager.get_scene_list()